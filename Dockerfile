ARG BUILD_FROM
FROM $BUILD_FROM

# Metadatos
LABEL maintainer="nupsterd"
LABEL description="Hikvision DS-K1T344 Face Terminal ISAPI Event Stream Listener for Home Assistant"

# Zona horaria del container
ENV TZ=America/Bogota

# Instalar Python 3 y dependencias del sistema
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-requests \
    tzdata && \
    cp /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

# Setup del directorio de trabajo
WORKDIR /app

# Copiar el código del listener
COPY hikvision_face_terminal/ /app/hikvision_face_terminal/

# Buena práctica: ejecutar como módulo, no como script
CMD ["python3", "-m", "hikvision_face_terminal.listener"]
