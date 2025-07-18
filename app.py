from flask import Flask, render_template, request
from zera import run_full_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        result = run_full_scan(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

