import os
import time
import threading
import psutil


# store last detected device to avoid repeated alerts
last_seen_usb = None


def start_usb_detection(callback):
    """
    Starts background USB detection thread.
    `callback` will be called when USB with key is detected.
    """
    t = threading.Thread(target=usb_detection_loop, args=(callback,), daemon=True)
    t.start()


def usb_detection_loop(callback):
    global last_seen_usb

    while True:
        result = detect_usb()

        if result and result != last_seen_usb:
            last_seen_usb = result
            callback(result)
        elif not result:
            last_seen_usb = None

        time.sleep(2)  # lightweight periodic scan


def detect_usb():
    """
    Scans mounted disks for 'encrypted_private_key.bin'.
    Returns (key_path, algorithm, private_key_bytes) if found.
    """

    for part in psutil.disk_partitions():

        # universal portable check
        if "removable" in part.opts or part.mountpoint.startswith(("/media", "/run/media")):
            mount = part.mountpoint
            key_path = os.path.join(mount, "encrypted_private_key.bin")

            if os.path.exists(key_path):
                try:
                    with open(key_path, "rb") as f:
                        raw = f.read()

                    # expected format: algo + b" " + private_key_bytes
                    if b" " in raw:
                        algo, key_bytes = raw.split(b" ", 1)
                        return key_path, algo.decode(), key_bytes

                except Exception as e:
                    print(f"USB read error: {e}")

    return None


# Example usage:
if __name__ == "__main__":

    def on_usb_detected(data):
        key_path, algo, priv = data
        print("=== USB KEY DETECTED ===")
        print("Path:", key_path)
        print("Algorithm:", algo)
        print("Key bytes:", priv[:20], "...")  # preview

    print("Starting USB monitor...")
    start_usb_detection(on_usb_detected)

    # keep main thread alive
    while True:
        time.sleep(1)
