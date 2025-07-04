FROM ubuntu:23.04
RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list && \
    apt update -y && \
    apt install -y xinetd && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN apt update -y && apt install -y gcc xinetd && apt clean && rm -rf /var/lib/apt/lists/*

RUN useradd -d /home/solver -u 8888 -M solver
RUN mkdir /home/solver
RUN chown root:root /home/solver

USER solver

COPY --chown=root:root xinetd /etc/xinetd.d/xinetd
COPY --chown=root:root app /home/solver

CMD ["/usr/sbin/xinetd", "-dontfork"]