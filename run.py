import os

import gradio as gr

import src.main as main
from src.config import settings

with gr.Blocks(css=main.CSS, title="Binary Analysis Agent") as demo:
    main.demo_block()

demo.launch(server_name=settings.GRADIO_SERVER_NAME, server_port= settings.GRADIO_SERVER_PORT, share=settings.GRADIO_SHARE)
