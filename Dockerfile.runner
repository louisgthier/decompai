# Use the official GCC image
# FROM gcc_linux_x86_64:latest
FROM kalilinux/kali-rolling:latest AS base

RUN apt update && apt -y install kali-linux-headless && rm -rf /var/lib/apt/lists/*

# Set environment variables for Ghidra
ENV GHIDRA_VERSION=11.3.1
ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip

# Download and install Ghidra
RUN wget -O /tmp/ghidra.zip $GHIDRA_URL && \
    unzip /tmp/ghidra.zip -d /opt && \
    rm /tmp/ghidra.zip && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC $GHIDRA_HOME

# Add Ghidra to PATH
ENV PATH="$GHIDRA_HOME:$GHIDRA_HOME/support:$PATH"


# # Install Java (required for Ghidra)
RUN apt-get update && apt-get install -y openjdk-21-jdk wget unzip && \
rm -rf /var/lib/apt/lists/*

# Install ninja and meson
RUN apt-get update && apt-get install -y ninja-build meson pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Install r2dec
RUN r2pm -U && \
    r2pm -i r2dec && \
    r2pm -ci r2ghidra

WORKDIR /

# Command to keep the container alive (if needed)
CMD ["bash"]