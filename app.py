from flask import Flask, render_template, request, jsonify
from analyzer.url_checks import analyze
from analyzer.whois_check import check_domain_age

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = analyze(url)
    whois = check_domain_age(url)
    result["checks"].insert(0, whois)
    passed = sum(1 for c in result["checks"] if c["ok"])
    result["score"] = round((passed / len(result["checks"])) * 100)
    result["risk"] = ("Low" if result["score"] >= 80 else
                      "Medium" if result["score"] >= 50 else "High")
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)