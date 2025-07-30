import os
import json
import csv
from datetime import datetime

# Create a reports folder if it doesn't exist
folder = "reports"
os.makedirs(folder, exist_ok=True)

def get_time():
    """
    Returns the current timestamp in YYYY-MM-DD_HH-MM-SS format.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def get_timestamp_iso():
    """
    Returns the current time in ISO 8601 format.
    """
    return datetime.now().isoformat()

def save_report_txt(data, link, score, result):
    """
    Saves the phishing report as a plain text file.
    """
    name = f"{folder}/report_{get_time()}.txt"
    with open(name, "w", encoding="utf-8") as file:
        file.write("Phishing Report\n")
        file.write("Time: " + get_timestamp_iso() + "\n")
        file.write("URL: " + link + "\n")
        file.write("Score: " + str(score) + "\n")
        file.write("Result: " + result + "\n\n")
        for key, value in data.items():
            file.write(f"{key}: {value}\n")
    print("TXT report saved:", name)

def save_report_json(data, link, score, result):
    """
    Saves the phishing report as a JSON file.
    """
    name = f"{folder}/report_{get_time()}.json"
    report_data = {
        "time": get_timestamp_iso(),
        "url": link,
        "score": score,
        "verdict": result,
        "data": data
    }
    with open(name, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)
    print("JSON report saved:", name)

def append_report_csv(data, link, score, result):
    """
    Appends a summary of the report to a single CSV file.
    """
    name = f"{folder}/summary_reports.csv"
    file_exists = os.path.isfile(name)

    fields = [
        "time", "url", "score", "verdict",
        "domain_age_months", "is_shortened_url", "suspicious_title",
        "suspicious_body", "forms_found", "contains_at_symbol",
        "dots_count", "url_length_long", "uses_https",
        "form_action_external", "url_contains_ip"
    ]

    row = {
        "time": get_timestamp_iso(),
        "url": link,
        "score": score,
        "verdict": result
    }

    for key in fields[4:]:
        row[key] = data.get(key, "N/A")

    with open(name, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

    print("CSV summary updated:", name)
