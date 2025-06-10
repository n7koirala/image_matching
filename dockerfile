# ------------------------------------------------------------------
# PETS 2025 Artifact – Image‑Matching (code + figures)
# ------------------------------------------------------------------
    FROM ubuntu:22.04

    ENV DEBIAN_FRONTEND=noninteractive \
        OFHE_VERSION=v1.2.3 \
        OFHE_DIR=/opt/openfhe
    
    # -------------------------------------------------
    # 1. System packages (python3 + venv + build deps)
    # -------------------------------------------------
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            ca-certificates \
            python3 python3-venv python3-pip \
            build-essential git cmake g++ \
            libjsonrpccpp-dev libjsonrpccpp-tools \
            libomp-dev openssl libssl-dev parallel && \
        rm -rf /var/lib/apt/lists/*
    
    # -------------------------------------------------
    # 2. OpenFHE (pinned tag v1.2.3)
    # -------------------------------------------------
    RUN git clone --depth 1 --branch ${OFHE_VERSION} \
            https://github.com/openfheorg/openfhe-development.git ${OFHE_DIR} && \
        mkdir ${OFHE_DIR}/build && \
        cd ${OFHE_DIR}/build && \
        cmake .. && make -j$(nproc) && make install && \
        ldconfig
    
    # -------------------------------------------------
    # 3. Project source (C++ build)
    # -------------------------------------------------
    WORKDIR /opt
    COPY . /opt/image_matching
    
    RUN mkdir /opt/image_matching/build && \
        cd /opt/image_matching/build && \
        cmake .. && \
        make -j$(nproc)
    
    # -------------------------------------------------
    # 4. Python virtual environment for figure scripts
    # -------------------------------------------------
    WORKDIR /opt/image_matching
    RUN python3 -m venv venv && \
        . venv/bin/activate && \
        pip install --no-cache-dir --upgrade pip && \
        pip install --no-cache-dir matplotlib pandas
    
    # Expose venv binaries to every subsequent shell
    ENV PATH="/opt/image_matching/venv/bin:${PATH}"
    
    # -------------------------------------------------
    # 5. Helper scripts
    # -------------------------------------------------
    COPY run_artifact.sh      /run_artifact.sh
    COPY generate_figures.sh  /generate_figures.sh
    RUN chmod +x /run_artifact.sh /generate_figures.sh
    
    # -------------------------------------------------
    # 6. Default action: smoke‑test   → figures
    # -------------------------------------------------
    ENTRYPOINT ["bash", "-c", "source /opt/image_matching/venv/bin/activate && /run_artifact.sh && /generate_figures.sh"]
    