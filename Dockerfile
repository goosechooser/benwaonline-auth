FROM goosechooser/benwaonline-base:0.0

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install .
