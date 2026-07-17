import os, subprocess, traceback, hashlib, requests
import gradio as gr
from androguard.core.bytecodes.apk import APK

def check_and_download_rules():
    rules_path = "/tmp/quark-rules"
    if not os.path.exists(rules_path):
        subprocess.run(["git", "clone", "https://github.com/quark-engine/quark-rules.git", rules_path], check=True)
    return f"{rules_path}/rules"

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    vt_api_key = os.environ.get("VT_API_KEY")
    if not vt_api_key:
        return {"error": "Chưa cấu hình VT_API_KEY"}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {"found": True, "malicious": stats['malicious'], "undetected": stats['undetected']}
        elif response.status_code == 404:
            return {"found": False, "message": "Tệp mới, chưa từng có trên cơ sở dữ liệu VirusTotal."}
        else:
            return {"error": f"Lỗi API: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def extract_permissions(file_path):
    try:
        apk = APK(file_path)
        return list(apk.get_permissions())
    except:
        return []

def scan_apk(file_path):
    if not file_path:
        return {"error": "Vui lòng tải lên một tệp APK hợp lệ."}
    
    # Kiểm tra dung lượng file (tính bằng MB)
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    
    # Bước 1: Trích xuất quyền & Quét VirusTotal (Khối lượng nhẹ, chạy được với file lớn)
    file_hash = get_file_hash(file_path)
    vt_report = check_virustotal(file_hash)
    permissions = extract_permissions(file_path)
    
    # Bước 2: Quét APKiD (Nhẹ, chạy bình thường)
    try:
        apkid_process = subprocess.run(['apkid', file_path], capture_output=True, text=True, timeout=60)
        apkid_result = apkid_process.stdout + apkid_process.stderr
    except Exception as e:
        apkid_result = f"LỖI APKiD: {str(e)}"

    # Bước 3: Quét Quark (Rất nặng, CHỈ quét nếu file < 40MB)
    quark_result = ""
    if file_size_mb <= 40:
        rules_dir = check_and_download_rules()
        try:
            quark_process = subprocess.run(['quark', '-a', file_path, '-r', rules_dir, '-s'], capture_output=True, text=True, timeout=180)
            quark_result = quark_process.stdout + quark_process.stderr
        except Exception as e:
            quark_result = f"LỖI QUARK: {str(e)}"
    else:
        # Trả về chuỗi giả lập báo cáo rỗng để Frontend không bị lỗi logic
        quark_result = "[!] CẢNH BÁO: File quá lớn (>40MB). Hệ thống bỏ qua phân tích Quark-Engine để bảo vệ máy chủ. Vui lòng dựa vào kết quả của VirusTotal."

    return {
        "vt_report": vt_report,
        "permissions": permissions,
        "apkid_report": apkid_result,
        "quark_report": quark_result
    }

demo = gr.Interface(fn=scan_apk, inputs=gr.File(type="filepath"), outputs="json")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    demo.launch(server_name="0.0.0.0", server_port=port, ssr_mode=False)
