# Explicit developer provisioning; eval run never downloads or builds runtimes.
FROM node@sha256:e7add2a490bb17d97b485b8641bd88455fff7839ade0f5eba493c3508124d413 AS node
FROM python@sha256:21206b8f02efda6d737e402e1c716b650ad30605843a36e4bcb55463a7ebdf37 AS python
FROM rust@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89
COPY --from=node /usr/local/ /usr/local/
COPY --from=python /usr/local/ /usr/local/
RUN ldconfig && npm install --global --ignore-scripts --no-audit --no-fund typescript@5.8.3
RUN python3 -m pip install --no-cache-dir fastapi==0.162.2 uvicorn==0.54.0 pytest==9.2.0 httpx==0.28.1
COPY --chmod=0555 toolchain.py /opt/rcode-toolchain/toolchain.py
RUN ["python3", "-I", "-S", "-c", "from pathlib import Path; p=Path('/opt/rcode-toolchain/bin'); p.mkdir(); [p.joinpath(name).symlink_to('../toolchain.py') for name in ('cargo','rustc','rustdoc','rustup')]"]
ENV PATH="/opt/rcode-toolchain/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin"
WORKDIR /
ENTRYPOINT ["python3", "-I", "-S", "/eval/runtime.py"]
