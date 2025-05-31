from flask import Flask, render_template, request, jsonify, send_file
import os
import pandas as pd
from openvas_scan import (
    start_scan_task,
    get_scan_progress,
    pause_task,
    resume_task
)
import torch  #
import joblib
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import OrdinalEncoder
import re
from transformers import T5Tokenizer, T5ForConditionalGeneration

app = Flask(__name__)
running_scans = {}  # Maps IP to task ID
completed_scans = {}  # Maps IP to completed scan result (if any)

# Path to the scan results directory
SCAN_RESULTS_DIR = 'scan_results/'
MODEL_PATH = 'models/severity_predictor.pkl'

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({"error": "Invalid IP address"}), 400

    ip_filename = ip.replace('.', '_') + ".csv"
    previous_scan_path = os.path.join(SCAN_RESULTS_DIR, ip_filename)

    # Check if a previous scan result exists
    if os.path.exists(previous_scan_path):
        return jsonify({
            "message": f"A previous scan for {ip} was found. Do you want to see the previous results or start a new scan?",
            "previous_scan_exists": True,
            "ip": ip
        })
    else:
        try:
            task_id = start_scan_task(ip)
            running_scans[ip] = task_id
            return jsonify({"message": f"Scan started for {ip}", "ip": ip, "previous_scan_exists": False})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route("/start_new_scan", methods=["POST"])
def start_new_scan():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        # Start a new scan for the selected IP address
        task_id = start_scan_task(ip)
        running_scans[ip] = task_id
        return jsonify({"message": f"New scan started for {ip}", "ip": ip, "previous_scan_exists": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/show_previous_scan/<ip>")
def show_previous_scan(ip):
    ip_filename = ip.replace('.', '_') + ".csv"
    previous_scan_path = os.path.join(SCAN_RESULTS_DIR, ip_filename)

    if os.path.exists(previous_scan_path):
        df = pd.read_csv(previous_scan_path)
        
        # Drop the "Solution" column before rendering the table
        if "solution" in df.columns:
            df = df.drop(columns=["solution"])
        
        # Convert the dataframe to HTML
        data_html = df.to_html(classes="table", header="true", index=False)
        return render_template("results.html", data_html=data_html, ip=ip)
    else:
        return jsonify({"error": "No previous scan found for this IP."}), 404

@app.route("/scan_status/<ip>")
def scan_status(ip):
    task_id = running_scans.get(ip)
    if not task_id:
        return jsonify({"status": "Not Found"}), 404
    try:
        status, progress = get_scan_progress(task_id)
        if status == "Done":
            # Mark the scan as completed and store the result
            ip_filename = ip.replace('.', '_') + ".csv"
            previous_scan_path = os.path.join(SCAN_RESULTS_DIR, ip_filename)
            if os.path.exists(previous_scan_path):
                completed_scans[ip] = pd.read_csv(previous_scan_path)
            else:
                completed_scans[ip] = None
        return jsonify({"status": status, "progress": progress})
    except Exception as e:
        return jsonify({"status": "Error", "error": str(e)}), 500

@app.route("/pause_scan/<ip>", methods=["POST"])
def pause_scan(ip):
    task_id = running_scans.get(ip)
    if not task_id:
        return jsonify({"error": "No running scan for this IP."}), 404
    try:
        pause_task(task_id)
        return jsonify({"message": "Scan paused."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/resume_scan/<ip>", methods=["POST"])
def resume_scan(ip):
    task_id = running_scans.get(ip)
    if not task_id:
        return jsonify({"error": "No paused scan for this IP."}), 404
    try:
        resume_task(task_id)
        return jsonify({"message": "Scan resumed."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/generate_classification/<ip>")
def generate_classification(ip):
    ip_filename = ip.replace('.', '_') + ".csv"
    scan_result_path = os.path.join(SCAN_RESULTS_DIR, ip_filename)

    if os.path.exists(scan_result_path):
        # Load the scan result CSV
        df = pd.read_csv(scan_result_path)

        # Model path and input
        if not os.path.exists(MODEL_PATH):
            return jsonify({"error": "Model not found."}), 404

        # Load model
        model = joblib.load(MODEL_PATH)

        # Clean description and predict severity
        df["cleaned_description"] = df["description"].apply(lambda x: re.sub(r'\s+', ' ', str(x).replace('\n', ' ')).strip())
        sbert_model = SentenceTransformer('all-MiniLM-L6-v2')
        embeddings = sbert_model.encode(df["cleaned_description"].tolist())
        embedding_df = pd.DataFrame(embeddings, columns=[f"sbert_{i}" for i in range(embeddings.shape[1])])
        
        # Prepare input for model prediction
        X = df[["access_vector", "access_complexity", "exploit", "cvss_score"]].copy()
        ord_enc = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)  # Correctly initialized
        X[["access_vector", "access_complexity", "exploit"]] = ord_enc.fit_transform(X[["access_vector", "access_complexity", "exploit"]])

        X_final = pd.concat([X.reset_index(drop=True), embedding_df.reset_index(drop=True)], axis=1)

        # Predict severity
        df["predicted_severity"] = model.predict(X_final)

        # Remove "cleaned_description" column from the report
        df = df.drop(columns=["cleaned_description", "solution"])  # Removed cleaned_description and solution columns

        # Save the new classification result
        result_filename = f"model_results/{ip.replace('.', '_')}_classification.csv"
        df.to_csv(result_filename, index=False)

        return jsonify({"message": f"Classification report for {ip} is generated."})
    else:
        return jsonify({"error": "Scan result not found."}), 404

@app.route("/show_classification_report/<ip>")
def show_classification_report(ip):
    result_filename = f"model_results/{ip.replace('.', '_')}_classification.csv"
    
    if os.path.exists(result_filename):
        df = pd.read_csv(result_filename)

        # Drop the "Solution" column before rendering
        if "solution" in df.columns:
            df = df.drop(columns=["solution"])

        data_html = df.to_html(classes="table", header="true", index=False)
        return render_template("classification.html", data_html=data_html, ip=ip)
    else:
        return jsonify({"error": "No classification report found for this IP."}), 404
        
# Define the route for generating the remediation report
@app.route("/generate_remediation_report/<ip>", methods=["GET"])
def generate_remediation_report(ip):
    ip_filename = ip.replace('.', '_') + ".csv"
    scan_result_path = os.path.join(SCAN_RESULTS_DIR, ip_filename)

    if os.path.exists(scan_result_path):
        # Log that the remediation report is being generated
        app.logger.info(f"Generating remediation report for IP: {ip} using {scan_result_path}")

        # Load the scan result CSV
        df = pd.read_csv(scan_result_path)

        # Load T5 model
        model_path = "models/t5_remediation_model"  
        tokenizer = T5Tokenizer.from_pretrained(model_path)
        model = T5ForConditionalGeneration.from_pretrained(model_path)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()

        df["remediation_steps"] = ""
        for idx, row in df.iterrows():
            input_text = f"cve_id: {row['cve_id']} description: {row['description']}"
            input_ids = tokenizer.encode(input_text, return_tensors="pt", truncation=True, max_length=512).to(device)

            with torch.no_grad():
                output_ids = model.generate(input_ids, max_new_tokens=100)
                remediation = tokenizer.decode(output_ids[0], skip_special_tokens=True)

            df.at[idx, "remediation_steps"] = remediation
        df_filtered = df[["cve_id", "cvss_score", "solution", "remediation_steps"]]
        remediation_filename = f"model_results/{ip.replace('.', '_')}_remediations.csv"
        df.to_csv(remediation_filename, index=False)

        # Log successful remediation report generation
        app.logger.info(f"Remediation report for IP: {ip} saved to {remediation_filename}")

        return jsonify({
            "message": f"Remediation report for {ip} is generated.",
            "remediation_report_generated": True
        })
    else:
        # Log error if scan result file is not found
        app.logger.error(f"Scan result not found for IP: {ip}")
        return jsonify({"error": "Scan result not found."}), 404


@app.route("/show_remediation_report/<ip>")
def show_remediation_report(ip):
    remediation_filename = f"model_results/{ip.replace('.', '_')}_remediations.csv"
    
    if os.path.exists(remediation_filename):
        df = pd.read_csv(remediation_filename)

        # Pass only the relevant columns to the template
        data = df[["cve_id", "cvss_score", "solution", "remediation_steps"]].to_dict(orient="records")

        return render_template("remediations.html", data=data, ip=ip)
    else:
        return jsonify({"error": "No remediation report found for this IP."}), 404



if __name__ == "__main__":
    app.run(debug=True)


