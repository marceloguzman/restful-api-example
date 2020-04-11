FROM python:3
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN python -m spacy download en_core_web_sm
RUN python -m spacy download es_core_news_sm
RUN pip install -U spacy

CMD ["python","app.py"]
