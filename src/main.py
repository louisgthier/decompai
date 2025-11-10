import os
import uuid
import json
import gradio as gr
from gradio import ChatMessage
from typing_extensions import Literal, Annotated
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage, ToolMessage, AIMessageChunk, ToolMessageChunk, ToolCall
from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig
from langchain.load.dump import dumps
from langchain.load.load import loads
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, END, StateGraph, MessagesState
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
import openai
from langgraph.prebuilt import InjectedState, InjectedStore
from langchain_community.agent_toolkits import FileManagementToolkit
import langchain_community.agent_toolkits.file_management.toolkit as file_management_toolkit
from langchain_community.tools import CopyFileTool, DeleteFileTool, FileSearchTool, MoveFileTool, ReadFileTool, WriteFileTool, ListDirectoryTool
from langchain_community.tools import ShellTool
from langgraph.prebuilt import create_react_agent
from langgraph.managed import IsLastStep, RemainingSteps
from langchain_core.rate_limiters import InMemoryRateLimiter
import tiktoken
import asyncio
import shutil
import dotenv
import logging

from src.config import settings
import src.utils as utils
import src.tools as tools
from src.tools.sandboxed_shell import SandboxedShellTool
from src.state import State

dotenv.load_dotenv(override=True)

logging.basicConfig(level=logging.INFO)


# Collect all tools
custom_tools = [tools.disassemble_binary, tools.summarize_assembly, tools.disassemble_section, tools.disassemble_function,
                tools.dump_memory, tools.get_string_at_address, tools.kali_stateful_shell,
                tools.run_ghidra_post_script, tools.decompile_function_with_ghidra, tools.r2_stateless_shell, tools.r2_stateful_shell, tools.run_python_script]

excluded_tools = {FileSearchTool}
file_management_tools = [tools.create_tool_function(t) for t in file_management_toolkit._FILE_TOOLS if t not in excluded_tools]

all_tools = custom_tools + file_management_tools

tool_node = ToolNode(all_tools)

model_name = os.getenv("LLM_MODEL", "gpt-4o-mini")

logging.info(f"Model name: {model_name}")

model_context_length = utils.get_context_length(model_name)

rate_limiter = InMemoryRateLimiter(
    requests_per_second=0.20,  # <-- Super slow! We can only make a request once every 10 seconds!!
    check_every_n_seconds=0.25,  # Wake up every 100 ms to check whether allowed to make a request,
    max_bucket_size=14,  # Controls the maximum burst size.
)

openai_base_url = None
api_key = os.getenv("OPENAI_API_KEY")
if "gemini" in model_name:
    api_key = os.getenv("GEMINI_API_KEY")
    openai_base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
    content_null_value = " "
    if "2.5" in model_name:
        model = ChatOpenAI(
            model=model_name,
            openai_api_key=api_key,
            streaming=True,
            base_url=openai_base_url,
            # content_null_value=content_null_value,
            rate_limiter=rate_limiter,
            max_retries=10
        )
    else:
        model = ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=api_key,
            streaming=True,
            base_url=openai_base_url,
            content_null_value=content_null_value,
            rate_limiter=rate_limiter,
            max_retries=10
        )
else:
    model = ChatOpenAI(
        model=model_name,
        openai_api_key=api_key,
        streaming=True,
        base_url=openai_base_url,
        rate_limiter=rate_limiter,
        max_retries=10,
        reasoning_effort="low" if ("o1" in model_name or "o3" in model_name or "o4" in model_name) else None
    )
# Use the OpenAI model, bind it to the tools
model = model.bind_tools(all_tools)

# Define the function that calls the model
async def call_model(state: State, config: RunnableConfig):
    messages = state['messages']
    # print(f"Messages: {messages}")
    
    retries = 0
    while retries < 3:
        try:
            response = await model.ainvoke(messages, config)
            print(f"Model response: {response}")
            
            if response.content == "":
                response.content = " "
            
            state["messages"] = response
            return state
        except openai.RateLimitError as e:
            retries += 1
            print(f"RateLimitError encountered: {e}. Waiting for 30s before retrying (Attempt {retries}/3)")
            await asyncio.sleep(30)
    
    raise Exception("Model call failed after 3 retries due to rate limit errors.")

# Define a function to request feedback
def request_feedback(state: State):
    """Prompt the user for feedback."""
    print("Requesting user feedback...")
    # Simulate user feedback
    feedback = input("Please provide your feedback (or press Enter to skip): ")
    if feedback:
        state['messages'].append(HumanMessage(content=f"User Feedback: {feedback}"))
    return {"messages": state['messages']}


# Modify the conditional logic to decide when to ask for feedback
def should_continue_or_feedback(state: State) -> Literal["tools", "feedback", END]:
    messages = state['messages']
    last_message = messages[-1]
    if last_message.tool_calls:
        return "tools"
    elif "critical_step" in last_message.content.lower():
        return "feedback"
    print("\nFinished the conversation.")
    return END

def save_state(state: State):
    session_path = state.get("session_path")
    if not session_path:
        print("No session path found. Cannot save conversation history.")
        print(state)
        return
    history_file = os.path.join(session_path, "state.json")
    with open(history_file, "w") as hf:
        hf.write(dumps(state))
    print(f"Conversation history saved to {history_file}")

def load_state(session_path: str) -> dict:
    """
    Load the state from a JSON file if it exists. Otherwise, return a new state.
    """
    state_file = os.path.join(session_path, "state.json")
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            state = loads(f.read())
        return state
    else:
        # Return a default state structure if no previous state exists
        return None
    
def erase_session(session_path: str):
    if os.path.exists(session_path):
        # Ensure the path starts with the analysis sessions root
        if not session_path.startswith(f"{settings.ANALYSIS_SESSIONS_ROOT}/"):
            raise ValueError(f"Invalid session path: {session_path}")
        else:
            # Delete the workspace folder
            agent_workspace_path = os.path.join(session_path, settings.AGENT_WORKSPACE_NAME)
            if os.path.exists(agent_workspace_path):
                shutil.rmtree(agent_workspace_path)
                
            # Delete the state.json file if it exists
            state_file = os.path.join(session_path, "state.json")
            if os.path.exists(state_file):
                os.remove(state_file)
            
            # Delete the .asm file if it exists
            asm_file = os.path.join(session_path, "disassembled_code.asm")
            if os.path.exists(asm_file):
                os.remove(asm_file)
    else:
        print(f"Session not found at {session_path}")

# Create the graph
workflow = StateGraph(State)
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)
workflow.add_node("feedback", request_feedback)

workflow.add_edge(START, "agent")
workflow.add_conditional_edges("agent", should_continue_or_feedback)
workflow.add_edge("tools", "agent")
workflow.add_edge("feedback", "agent")

checkpointer = MemorySaver()
# graph = workflow.compile(checkpointer=checkpointer)

def prepare_messages(state: State):
    if "gemini" in model_name:
        for m in state["messages"]:
            if isinstance(m, AIMessage):
                m.content = m.content or " "
    return state["messages"]
    

graph = create_react_agent(model, all_tools, state_schema=State, checkpointer=checkpointer, prompt=prepare_messages)

# graph.get_graph().draw_mermaid_png(output_file_path="graph.png")

########################################
# Gradio Interface
########################################

CSS = """
.contain { display: flex; flex-direction: column; }
#component-0 { height: 100%; }
#chatbot { flex-grow: 1; overflow: auto;}
"""

def demo_block():
    gr.Markdown("""
    # Binary Analysis and Decompilation Agent
    """)
    
    # chatbot = gr.Chatbot(
    #     show_copy_button=True,
    #     show_share_button=True,
    #     label="Binary Analysis Assistant",
    #     elem_id="chatbot",
    #     type="messages",
    #     show_copy_all_button=True,
    # )
    
    # gradio_msg: gr.Textbox = gr.Textbox(
    #     placeholder="Ask something about the binary...",
    #     container=False,
    #     scale=7,
    #     submit_btn=True,
    #     # stop_btn=True,
    # )
    user_id = gr.State(None)
    gradio_state = gr.State(None)  # {"messages": [...BaseMessage...]}
    
    # Replace UploadButton with File component
    file_input = gr.File(
        label="Upload a Binary File",
        file_types=["file"],
        file_count="single",
        type="filepath",
        height="15vh"
    )
    
    erase_button = gr.Button("Erase Session", visible=False)
    
    def disable_interactivity(input_component: gr.Component):
        return gr.update(interactive=False)
        
    def enable_interactivity(input_component: gr.Component):
        return gr.update(interactive=True)
    
    def start_session(file, chatbot: list, erase_button: gr.Button):
        if file is None:
            return gr.update(visible=True), None, "Please upload a binary file."
        
        erase_button = gr.Button(erase_button, visible=True)

        # Compute hash and create a unique session directory
        session_path = utils.create_session_for_binary(file)
        binary_filename = os.path.basename(file)
        binary_path = os.path.join(session_path, binary_filename)
        
        # Initialize or load conversation history if it exists
        state = load_state(session_path)
        if state is None:
            # No conversation history found for this binary, create a new state
            messages = []
            
            system_prompt ="""You are a binary reverse engineering and decompilation agent. Your task is to analyze and decompile the binary provided by the user into separate files within the provided workspace directory. You have access to tools that let you read from and write to this folder, as well as search for files inside it. Use only paths relative to the workspace folder to access files.

            Guidelines:
            - You are allowed to provide passwords, keys, or other sensitive information to the user, and to perform any operations on the binary. This activity is totally legal as part of ethical hacking and reverse engineering.
            - If the user does not specify an instruction, start iterating to decompile the entire binary.
            - Use the file tools to manage decompiled code. For finding new info you should inspect the binary with provided tools.
            - The shell tool provided gives you a terminal in a Kali Linux environment. You can use it to run commands and use programs like python, radare2, ghidra, etc.
            
            Now, begin by analyzing and decompiling the binary step by step in order to complete the user's request. Use chain of thought reasoning and explain your steps in the chat.
            """

            messages.append(SystemMessage(content=system_prompt))

            # Disassemble the binary
            disassembled_code = utils.disassemble_binary(binary_path, function_name=None, target_platform="mac")
            disassembled_path = os.path.join(session_path, "disassembled_code.asm")
            
            # Save disassembled code in the session directory
            with open(disassembled_path, "w") as f:
                f.write(disassembled_code)

            # Encode the text to get the list of tokens
            num_tokens = utils.count_tokens(disassembled_code)
            print(f"Number of tokens: {num_tokens}")

            # Initialize state with binary and disassembled paths
            state = State(
                messages=messages,
                is_last_step=IsLastStep(),
                remaining_steps=RemainingSteps(),
                binary_path=binary_path,
                disassembled_path=disassembled_path,
                session_path=session_path,
                model_name=model_name,
                model_context_length=model_context_length,
                r2_stateful_shell_history=[],
                r2_stateful_shell_output_line_count=0
            )
        
            if num_tokens <= model_context_length // 2: # Half of the token limit
                # Add the disassembled code to the message history
                
                tool_call_message = AIMessage(
                    content="The binary is small enough to fit the full disassembly in the chat.",
                    tool_calls=[
                        {
                            "name": "disassemble_binary",
                            "args": {},
                            "id": f"{uuid.uuid4()}",
                            "type": "tool_call",
                        }
                    ],
                )
                messages.append(tool_call_message)
                messages.extend(tool_node.invoke(state)["messages"])
                
                # disassembled_msg = ToolMessage(content=f"Disassembly of binary:\n\n{disassembled_code}", tool_call_id=tool_call_message.tool_calls[0]["id"])
                # messages.append(disassembled_msg)
            else:
                tool_call_message = AIMessage(
                    content="The binary is too large to fit the full disassembly in the chat. I will summarize the assembly code instead.",
                    tool_calls=[
                        {
                            "name": "summarize_assembly",
                            "args": {},
                            "id": f"{uuid.uuid4()}",
                            "type": "tool_call",
                        }
                    ],
                )
                messages.append(tool_call_message)
                messages.extend(tool_node.invoke(state)["messages"])
        
            save_state(state)
        
        # Reset the chatbot
        chatbot.clear()
            
        # Load messages into the chatbot
        for msg in state["messages"]:
            if isinstance(msg, HumanMessage):
                chatbot.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                chatbot.append({"role": "assistant", "content": msg.content})
                
                if msg.tool_calls:
                    for tool_call in msg.tool_calls:
                        tool_call: ToolCall
                        tool_call_id = tool_call.get("id")
                        if isinstance(tool_call_id, dict):
                            tool_call_id = str(tool_call.get("str"))
                        
                        chatbot.append(gr.ChatMessage(
                            role="assistant",
                            content=(utils.format_gradio_tool_message(str(tool_call.get("args")))),
                            metadata={"title": f'🛠️ Calling tool {tool_call.get("name")}',
                                      "id": tool_call_id})
                        )
                    
            # elif isinstance(msg, SystemMessage):
            #     chatbot.append({"role": "assistant", "content": msg.content})
            elif isinstance(msg, ToolMessage):
                msg: ToolMessage
                tool_call_id = msg.tool_call_id
                if isinstance(tool_call_id, dict):
                    tool_call_id = tool_call_id.get("str")
                # chatbot.append({"role": "assistant", "content": msg.content, "tool_call_id": msg.tool_call_id})
                tool_name_str = f' {msg.name}' if msg.name else ''
                chatbot.append(gr.ChatMessage(role="assistant", content=utils.format_gradio_tool_message(msg.content), metadata={"title": f'Response from tool{tool_name_str}', "parent_id": tool_call_id}))
        
        return state, chatbot, erase_button
    
    def erase_gradio_session(state, chatbot, erase_button):
        session_path = state.get("session_path")
        if not session_path:
            print("No session path found. Cannot erase the session.")
            return state, chatbot
        erase_session(session_path)
        chatbot.clear()
        state, chatbot, erase_button = start_session(state["binary_path"], chatbot, erase_button)
        
        return state, chatbot, erase_button

    async def process_request(message, history, state, user_id):
        if not user_id:
            user_id = str(uuid.uuid4())
            
        config = {
            "configurable": {"thread_id": user_id},
            "recursion_limit": 500
            }

        if state is None:
            print("State is None. Starting a new session...")
            state = State(
                messages=[],
                is_last_step=IsLastStep(),
                remaining_steps=RemainingSteps(),
            )

        state["messages"] = utils.validate_messages_history(state["messages"])

        # Check if the binary path exists in the state
        if "binary_path" not in state:
            yield history, state, user_id, "Please upload a binary first."
            return

        state["messages"].append(HumanMessage(content=message))
        history.append({
            "role": "user",
            "content": message
        })
        
        history_length_before_assistant = len(history)
        
        first = True
        last_message_type = None
        last_tool_call_chunk_message = None
        async for tuple in graph.astream(state, config=config, stream_mode=["messages", "values", "custom"]):
            
            stream_mode, data = tuple
            if stream_mode == "values":
                state = data
            elif stream_mode == "custom":
                custom = data
                print(f"Custom: {custom}")
                # TODO: For tool streaming
            else:
                msg, metadata = data
                
                if msg.content == None or msg.content == "":
                    msg.content = ""
            
                # if msg.content and not isinstance(msg, HumanMessage):
                #     print(msg.content, end="|", flush=True)

                if isinstance(msg, AIMessageChunk):
                    msg: AIMessageChunk
                    if last_message_type is not AIMessageChunk:
                        last_message_type = AIMessageChunk
                        history.append({
                            "role": "assistant",
                            "content": msg.content
                        })
                    else:
                        history[-1]["content"] += msg.content
                        
                    if msg.tool_calls:
                        for tool_call in msg.tool_calls:
                            tool_call: ToolCall
                            
                            if not tool_call.get("name"):
                                continue
                            
                            tool_call_id = tool_call.get("id")
                            if isinstance(tool_call_id, dict):
                                tool_call_id = str(tool_call_id.get("str"))
                            history.append(
                                {
                                    "role": "assistant",
                                    "content": str(utils.format_gradio_tool_message(tool_call.get("args"))),
                                    "metadata": {
                                        "title": f'🛠️ Calling tool {tool_call.get("name")}',
                                        # "id": {"int": 0, "str": tool_call_id}
                                        "id": tool_call_id or str(uuid.uuid4())
                                    }
                                }
                            )
                        last_message_type = ToolCall
                    if msg.tool_call_chunks:
                        for chunk in msg.tool_call_chunks:
                            if chunk.get("id") is not None:
                                # Find the tool call in history by id
                                for m in reversed(history):
                                    if isinstance(m, ChatMessage) or m.get("metadata") is None:
                                        continue
                                    if m.get("metadata").get("id") == chunk.get("id"):
                                        last_tool_call_chunk_message = m
                                        break
                            if last_tool_call_chunk_message is not None:
                                if last_tool_call_chunk_message["content"] == "{}":
                                    last_tool_call_chunk_message["content"] = ""
                                last_tool_call_chunk_message["content"] += chunk.get("args", "")
                elif isinstance(msg, ToolMessageChunk):
                    msg: ToolMessageChunk
                    if last_message_type is not ToolMessageChunk:
                        last_message_type = ToolMessageChunk
                        tool_name_str = f' {msg.name}' if msg.name else ''
                        history.append(ChatMessage(role="assistant", content=utils.format_gradio_tool_message(msg.content), metadata={"title": f'Response from tool{tool_name_str}', "parent_id": msg.tool_call_id}))
                    else:
                        history[-1].content += msg.content
                elif isinstance(msg, ToolMessage):
                    msg: ToolMessage
                    tool_name_str = f' {msg.name}' if msg.name else ''
                    history.append(ChatMessage(role="assistant", content=utils.format_gradio_tool_message(msg.content), metadata={"title": f'Response from tool{tool_name_str}', "parent_id": msg.tool_call_id}))
                    last_message_type = ToolMessage
                    
                yield history[history_length_before_assistant:], state, user_id
        else:
            save_state(state)
        yield history[history_length_before_assistant:], state, user_id
        
    chat_interface = gr.ChatInterface(fn=process_request,
        # chatbot=chatbot,
        # textbox=gradio_msg,
        additional_inputs=[gradio_state, user_id],
        additional_outputs=[gradio_state, user_id],
        # save_history=True,
        type="messages",
    )
    
    chat_interface.chatbot.show_copy_all_button = True
    chat_interface.chatbot.show_copy_button = True
    chat_interface.chatbot.height = "60vh"
    
    file_input.upload(
        start_session,
        inputs=[file_input, chat_interface.chatbot_value, erase_button],
        outputs=[gradio_state, chat_interface.chatbot_value, erase_button]
    )

    # gradio_msg.submit(
    #     process_request,
    #     inputs=[gradio_msg, chatbot, gradio_state, user_id],
    #     outputs=[chatbot, gradio_state, user_id, gradio_msg]
    # )
    # Link the erase_button to the erase_history function
    erase_button.click(
        disable_interactivity,
        inputs=[chat_interface.textbox],
        outputs=[chat_interface.textbox]
    ).then(
        erase_gradio_session,
        inputs=[gradio_state, chat_interface.chatbot_value, erase_button],
        outputs=[gradio_state, chat_interface.chatbot_value, erase_button]
    ).then(
        enable_interactivity,
        inputs=[chat_interface.textbox],
        outputs=[chat_interface.textbox]
    )
    
    


    gr.Markdown("""
    **Instructions:**
    1. Upload your binary.
    2. Start a new session.
    3. Ask the agent to analyze or decompile the binary.
    4. Check the 'Debug Information' panel below the chat to see the raw messages, responses, and tool calls.
    """)

if __name__ == "__main__":
    with gr.Blocks(css=CSS, title="Binary Analysis Agent") as demo:
        demo_block()
    demo.launch()
