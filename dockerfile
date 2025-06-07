# ------------------------------------------------------------------
# PETS 2025 Artifact
# Builds the full environment, compiles OpenFHE v1.2.3 + the project,
# generates example datasets, and leaves an ENTRYPOINT that executes
# a fast smoke‑test.
# ------------------------------------------------------------------
    FROM ubuntu:22.04

    ENV DEBIAN_FRONTEND=noninteractive \
        OFHE_VERSION=v1.2.3 \
        OFHE_DIR=/opt/openfhe
    
    # -------- System dependencies --------
    RUN apt-get update && \
        apt-get install -y --no-install-recommends \
            ca-certificates \ 
            build-essential git cmake g++ \
            libjsonrpccpp-dev libjsonrpccpp-tools \
            libomp-dev openssl libssl-dev parallel && \
        mkdir -p /usr/local/include /usr/local/lib && \
        rm -rf /var/lib/apt/lists/*
    
    # -------- OpenFHE (pinned tag) --------
    RUN git clone --depth 1 --branch ${OFHE_VERSION} \
            https://github.com/openfheorg/openfhe-development.git ${OFHE_DIR} && \
        mkdir ${OFHE_DIR}/build && \
        cd ${OFHE_DIR}/build && \
        cmake .. && make -j$(nproc) && make install && \
        ldconfig
    
    # -------- Project source --------
    WORKDIR /opt
    COPY . /opt/image_matching
    RUN mkdir /opt/image_matching/build && \
        cd /opt/image_matching/build && \
        cmake .. && \
        make -j$(nproc)
    
    # -------- Prepare example data --------
    # RUN cd /opt/image_matching/build && \
    #     ../tools/setup_experiment.sh && \
    #     ../tools/gen_all_datasets.sh
    
    # -------- Helper scripts --------
    COPY run_artifact.sh /run_artifact.sh
    RUN chmod +x /run_artifact.sh
    
    ENTRYPOINT ["/run_artifact.sh"]
    
