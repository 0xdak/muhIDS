from flask import Flask, redirect, render_template, request

app = Flask(__name__, template_folder='.')

@app.route('/',methods = ['POST', 'GET'])
def home():
    if request.method == 'POST':
        return redirect("http://ehm.kocaeli.edu.tr", code=302)
    return render_template("index.html")

if __name__ == "__main__":
      app.run(host='0.0.0.0', port=80)