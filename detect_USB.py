import os
import psutil
import state
import time
import threading
import glob

def start_usb_detection_thread():
    detection_thread = threading.Thread(target=usb_detection_loop, daemon=True)
    detection_thread.start()


def usb_detection_loop():
    while True:
        detection = detect_usb()
        if detection:
            state.usb_path_queue.put(detection)
            state.usb_detected_event.set()
        time.sleep(3)


def detect_usb():
    import state

    for partition in psutil.disk_partitions():
        

        if "removable" in partition.opts:
            mount = partition.mountpoint

            found_public = None
            found_private = None

            for i, pub_path in enumerate(glob.glob(os.path.join(mount, "*.pub"))):
                if state.skip_public_key == i % glob.glob(os.path.join(mount, "*.pub")).__len__():
                    try:
                        with open(pub_path, "rb") as f:
                            raw = f.read()
                        algo, key = raw.split(b" ", 1)

                        if state.last_public_seen != pub_path:
                            found_public = ("public", pub_path, algo.decode(), key)

                    except Exception as e:
                        print(f"[USB ERROR reading Public] {e}")

            for i, priv_path in enumerate(glob.glob(os.path.join(mount, "*.key"))):
                if state.skip_private_key == i % glob.glob(os.path.join(mount, "*.key")).__len__():
                    try:
                        with open(priv_path, "rb") as f:
                            raw = f.read()
                        algo, key = raw.split(b" ", 1)

                        if state.last_private_seen != priv_path:
                            found_private = ("private", priv_path, algo.decode(), key)

                    except Exception as e:
                        print(f"[USB ERROR reading Private] {e}")

            if state.skip_public_key > glob.glob(os.path.join(mount, "*.pub")).__len__():
                state.skip_public_key = 0

            if state.skip_private_key > glob.glob(os.path.join(mount, "*.key")).__len__():
                state.skip_private_key = 0

            if found_private:
                state.last_private_seen = found_private[1]
                print(f"[USB] New PRIVATE key detected: {priv_path}")
                return found_private

            if found_public:
                state.last_public_seen = found_public[1]
                print(f"[USB] New PUBLIC key detected: {pub_path}")
                return found_public

    return None
