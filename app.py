import os, subprocess, traceback
import gradio as gr

def check_and_download_rules():
    rules_path = "/tmp/quark-rules"
    if not os.path.exists(rules_path):
        print("Đang tải Quark-Rules từ GitHub...")
        try:
            subprocess.run(["git", "clone", "https://github.com/quark-engine/quark-rules.git", rules_path], check=True)
        except Exception as e:
            print(f"Lỗi tải rules: {e}")
    return f"{rules_path}/rules"

def scan_apk(file_path):
    if not file_path:
        return {"error": "Vui lòng tải lên một tệp APK hợp lệ."}
    
    rules_dir = check_and_download_rules()
    
    # Bước 1: Quét APKiD
    try:
        apkid_process = subprocess.run(
            ['apkid', file_path], 
            capture_output=True, text=True, timeout=60
        )
        apkid_result = apkid_process.stdout + apkid_process.stderr
    except subprocess.TimeoutExpired:
        apkid_result = "LỖI [TIMEOUT]: APKiD vượt quá thời gian 60 giây chờ đợi."
    except Exception as e:
        apkid_result = f"LỖI [HỆ THỐNG APKiD]:\n{traceback.format_exc()}"

    # Bước 2: Quét Quark
    try:
        quark_process = subprocess.run(
            ['quark', '-a', file_path, '-r', rules_dir, '-s'], 
            capture_output=True, text=True, timeout=120
        )
        quark_result = quark_process.stdout + quark_process.stderr
    except subprocess.TimeoutExpired:
        quark_result = "LỖI [TIMEOUT]: Quark-Engine vượt quá thời gian chờ đợi."
    except Exception as e:
        quark_result = f"LỖI [HỆ THỐNG QUARK]:\n{traceback.format_exc()}"

    return {
        "apkid_report": apkid_result,
        "quark_report": quark_result
    }

# Xây dựng giao diện Gradio
demo = gr.Interface(
    fn=scan_apk,
    inputs=gr.File(label="Tải lên tệp APK của bạn", type="filepath"),
    outputs=gr.JSON(label="Báo cáo phân tích"),
    title="🛡️ Máy chủ Phân tích Mã độc APK",
    description="Hệ thống quét bằng APKiD và Quark-Engine. Bạn có thể kéo thả tệp trực tiếp trên web hoặc gửi qua API."
)

if __name__ == "__main__":
    # Sử dụng biến môi trường PORT của Render, nếu không có thì chạy mặc định 10000
    port = int(os.environ.get("PORT", 10000))
    demo.launch(server_name="0.0.0.0", server_port=port, ssr_mode=False)