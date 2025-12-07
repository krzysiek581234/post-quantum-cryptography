import os
import psutil
import globals
import time
import threading


def start_usb_detection_thread():
    detection_thread = threading.Thread(target=usb_detection_loop, daemon=True)
    detection_thread.start()


def usb_detection_loop():
    while True:
        detection = detect_usb()
        if detection:  # detection = (path, algo, key_bytes)
            globals.usb_path_queue.put(detection)
            globals.usb_detected_event.set()
        time.sleep(3)  # check frequently, but not aggressively


def detect_usb():
    """
    Szuka pendrive'a, sprawdza czy zawiera klucz prywatny
    i zwraca tuple: (ścieżka, algorytm, klucz binarny)
    """

    for partition in psutil.disk_partitions():
        if "removable" in partition.opts:
            mount = partition.mountpoint
            key_path = os.path.join(mount, "encrypted_private_key.bin")

            if os.path.exists(key_path):

                try:
                    with open(key_path, "rb") as f:
                        raw = f.read()

                    algo, priv_key = raw.split(b" ", 1)
                    algo = algo.decode()

                    return key_path, algo, priv_key

                except Exception as e:
                    print(f"[USB ERROR] Nie udalo sie wczytac klucza: {e}")

    return None
