import json
import logging
from datetime import datetime, timedelta

from flask import Flask, redirect, url_for, session, request, render_template, flash

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    # Initialize logging for console
    log_formatter = logging.Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(log_formatter)

    app.logger.addHandler(stream_handler)
    app.logger.setLevel(logging.DEBUG)

    app.logger.info("Starting Flask application...")
    app.run(debug=True, port=5004)
