FROM golang:alpine as build
RUN ["apk", "add", "upx"]
ADD . /TLSAutomate
ENV CGO_ENABLED 0

WORKDIR /TLSAutomate
RUN ["go", "mod", "download"]
RUN ["go", "generate", "./..."]
RUN ["go", "build", "-ldflags", "-s -w", "."]
RUN ["upx", "TLSAutomate"]

WORKDIR entrypoint
RUN ["go", "build", "-ldflags", "-s -w", "."]
RUN ["upx", "entrypoint"]


FROM golang:alpine as cas
RUN ["apk", "add", "ca-certificates"]


FROM golang:alpine as empty
RUN ["mkdir", "/empty"]


FROM scratch

COPY --from=cas /etc/ssl/certs /etc/ssl/certs
COPY --from=empty /empty /data
COPY --from=build /TLSAutomate/TLSAutomate /TLSAutomate
COPY --from=build /TLSAutomate/entrypoint/entrypoint /entrypoint

WORKDIR /data
CMD ["/entrypoint"]
