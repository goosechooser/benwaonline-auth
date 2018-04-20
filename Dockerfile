FROM python:3.6 as packages
COPY requirements.txt .
RUN pip wheel --wheel-dir=/tmp/wheelhouse -r requirements.txt

FROM python:3.6 as testing
COPY requirements.txt .
COPY requirements-testing.txt .
COPY --from=packages /tmp/wheelhouse /tmp/wheelhouse

RUN pip install --no-index --find-links=/tmp/wheelhouse -r requirements.txt
RUN pip install -r requirements-testing.txt
RUN find . -name "*.pyc" -delete

COPY . /testing/
WORKDIR /testing
RUN mkdir reports

FROM python:3.6
COPY requirements.txt .
COPY --from=packages /tmp/wheelhouse /tmp/wheelhouse
RUN pip install --no-index --find-links=/tmp/wheelhouse -r requirements.txt

WORKDIR /usr/src/app
COPY . .
