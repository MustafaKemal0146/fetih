#!/usr/bin/env python3
"""FETİH Desktop Bridge - Uçtan Uca Duman Testi (End-to-End Smoke Test).

1. Bridge sunucusunu subprocess olarak başlatır.
2. Anons edilen WebSocket portu ve tek kullanımlık belirteci okur.
3. WebSockets üzerinden bağlanıp el sıkışır (authenticate).
4. session.create -> session.send (session.thought, session.delta, session.done olaylarını toplar)
   -> session.list -> session.load -> session.rename -> session.delete
   zincirini koşturur ve tüm yanıtları doğrular.
5. Sunucuyu temiz şekilde sonlandırır.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import websockets
except ImportError:
    print("HATA: 'websockets' kütüphanesi bulunamadı.", file=sys.stderr)
    sys.exit(1)


async def run_smoke_test():
    print("FETİH Desktop Bridge - Duman Testi Başlatılıyor...")
    print("=" * 60)

    # 1. Sunucu sürecini başlat
    root_dir = Path(__file__).resolve().parent.parent
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["FETIH_BRIDGE_MOCK_AGENT"] = "1"

    cmd = [sys.executable, "-m", "fetih_desktop_bridge", "--port", "0"]
    print(f"Sunucu başlatılıyor: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        cwd=str(root_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    ws_url = None
    token = None

    try:
        # 2. İlk satırdan bridge.listening bilgisini yakala
        start_time = time.time()
        while time.time() - start_time < 10:
            line = proc.stdout.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("event") == "bridge.listening":
                    ws_url = data.get("url")
                    token = data.get("token")
                    print(f"✓ Sunucu hazır! URL: {ws_url}")
                    break
            except json.JSONDecodeError:
                continue

        if not ws_url or not token:
            stderr_out = proc.stderr.read()
            raise RuntimeError(f"Sunucu el sıkışma satırı okunamadı. Stderr: {stderr_out}")

        # 3. WebSocket bağlantısı aç
        print(f"WebSocket ile bağlanılıyor: {ws_url} ...")
        async with websockets.connect(ws_url) as ws:
            print("✓ WebSocket bağlantısı kuruldu.")

            req_id = 0
            pending_responses: dict[int, asyncio.Future] = {}
            received_events: list[dict] = []

            async def receiver():
                try:
                    async for raw_msg in ws:
                        frame = json.loads(raw_msg)
                        if "id" in frame and frame["id"] in pending_responses:
                            pending_responses[frame["id"]].set_result(frame)
                        else:
                            received_events.append(frame)
                except asyncio.CancelledError:
                    pass
                except Exception as ex:
                    print(f"Alıcı istisnası: {ex}", file=sys.stderr)

            rx_task = asyncio.create_task(receiver())

            async def rpc_call(method: str, params: dict | None = None, timeout: float = 10.0) -> dict:
                nonlocal req_id
                req_id += 1
                curr_id = req_id
                future = asyncio.get_running_loop().create_future()
                pending_responses[curr_id] = future
                payload = {
                    "jsonrpc": "2.0",
                    "id": curr_id,
                    "method": method,
                    "params": params or {},
                }
                await ws.send(json.dumps(payload))
                res = await asyncio.wait_for(future, timeout=timeout)
                del pending_responses[curr_id]
                return res

            try:
                # 4. Kimlik Doğrulama (Authenticate)
                print("\n[Adım 1] bridge.authenticate çağrılıyor...")
                auth_res = await rpc_call("bridge.authenticate", {"token": token})
                assert auth_res.get("result", {}).get("authenticated") is True, f"Kimlik doğrulama başarısız: {auth_res}"
                print("✓ bridge.authenticate başarılı.")

                # 5. session.create
                print("\n[Adım 2] session.create çağrılıyor...")
                sid = f"smoke-{int(time.time())}"
                create_res = await rpc_call("session.create", {"session_id": sid, "title": "Smoke Session Test"})
                assert "result" in create_res, f"session.create hatası: {create_res}"
                assert create_res["result"]["session_id"] == sid
                print(f"✓ session.create başarılı: {sid}")

                # 6. session.send ve olayların akışı
                print("\n[Adım 3] session.send çağrılıyor ve akış olayları dinleniyor...")
                send_future = asyncio.create_task(
                    rpc_call("session.send", {"session_id": sid, "message": "Merhaba test", "stream": True}, timeout=15.0)
                )

                # Olayları bekle: session.thought, session.delta, session.done
                wait_start = time.time()
                thought_received = False
                delta_received = False
                done_received = False

                while time.time() - wait_start < 12:
                    for ev in received_events:
                        method = ev.get("method")
                        p = ev.get("params", {})
                        if p.get("session_id") == sid:
                            if method == "session.thought":
                                thought_received = True
                            elif method == "session.delta":
                                delta_received = True
                            elif method == "session.done":
                                done_received = True

                    if thought_received and delta_received and done_received:
                        break
                    await asyncio.sleep(0.1)

                send_res = await send_future
                assert "result" in send_res, f"session.send hatası: {send_res}"
                assert thought_received, "HATA: session.thought olayı alınamadı!"
                assert delta_received, "HATA: session.delta olayı alınamadı!"
                assert done_received, "HATA: session.done olayı alınamadı!"
                print("✓ session.send tamamlandı; session.thought, session.delta ve session.done başarıyla alındı.")

                # 7. session.list
                print("\n[Adım 4] session.list çağrılıyor...")
                list_res = await rpc_call("session.list", {})
                assert "result" in list_res, f"session.list hatası: {list_res}"
                sessions = list_res["result"].get("sessions", [])
                matching = [s for s in sessions if s.get("id") == sid or s.get("session_id") == sid]
                assert len(matching) >= 1, f"Oturum {sid} listede bulunamadı!"
                print(f"✓ session.list başarılı, oturum listede mevcut (toplam {len(sessions)} oturum).")

                # 8. session.load
                print("\n[Adım 5] session.load çağrılıyor...")
                load_res = await rpc_call("session.load", {"session_id": sid})
                assert "result" in load_res, f"session.load hatası: {load_res}"
                items = load_res["result"].get("items", [])
                assert len(items) > 0, "session.load içinde transkript öğeleri boş!"
                print(f"✓ session.load başarılı, {len(items)} transkript öğesi yüklendi.")

                # 9. session.rename
                print("\n[Adım 6] session.rename çağrılıyor...")
                new_title = "Smoke Session Renamed"
                rename_res = await rpc_call("session.rename", {"session_id": sid, "title": new_title})
                assert "result" in rename_res, f"session.rename hatası: {rename_res}"
                assert rename_res["result"]["title"] == new_title
                print(f"✓ session.rename başarılı: '{new_title}'")

                # 10. session.delete
                print("\n[Adım 7] session.delete çağrılıyor...")
                del_res = await rpc_call("session.delete", {"session_id": sid})
                assert "result" in del_res, f"session.delete hatası: {del_res}"
                assert del_res["result"].get("deleted") is True

                # Silindiğini listeden doğrula
                verify_list = await rpc_call("session.list", {})
                remaining = [s for s in verify_list["result"].get("sessions", []) if s.get("id") == sid or s.get("session_id") == sid]
                assert len(remaining) == 0, f"Oturum {sid} silindikten sonra hala listede!"
                print("✓ session.delete başarılı, oturum silindi ve listeden kaldırıldı.")

            finally:
                rx_task.cancel()

    finally:
        print("\nSunucu kapatılıyor...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("✓ Sunucu sonlandırıldı.")

    print("\n" + "=" * 60)
    print("SONUÇ: BÜTÜN DUMAN TESTLERİ BAŞARIYLA GEÇTİ!")


def main():
    asyncio.run(run_smoke_test())


if __name__ == "__main__":
    main()
