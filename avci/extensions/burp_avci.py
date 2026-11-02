# -*- coding: utf-8 -*-
# ==========================================================================
# AVCI Mirror — Burp Suite eklentisi (Jython 2.7)
#
# What it does: sends a copy of EVERY request/response pair passing through
# Burp (Proxy, Repeater, all tools) to AVCI's local ingest server. The
# traffic flow does NOT change — this is just a mirror; it doesn't block,
# modify, or delay requests (sending happens on a separate thread, 2s
# timeout).
#
# Kurulum:
#   1) jython-standalone-2.7.x.jar indir (Maven Central)
#   2) Burp: Extensions → Extension settings → Python environment
#      → select the jar's path
#   3) Burp: Extensions → Add → Extension type: Python → select this file
#   4) On the AVCI side:  avci ingest   (listens on 127.0.0.1:9090)
# ==========================================================================
from burp import IBurpExtender, IHttpListener

import base64
import json
import threading
import urllib2

INGEST_URL = "http://127.0.0.1:9090/ingest"
TIMEOUT_SN = 2


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AVCI Mirror")
        callbacks.registerHttpListener(self)
        callbacks.printOutput("AVCI Mirror ready -> " + INGEST_URL)
        callbacks.printOutput("'avci ingest' must be running on the AVCI side.")

    # mirror only when the response arrives (when the pair is complete)
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            payload = self._build_payload(messageInfo)
            if payload is not None:
                threading.Thread(target=self._send, args=(payload,)).start()
        except Exception as exc:
            self._callbacks.printError("AVCI ayna hatasi: " + repr(exc))

    # ------------------------------------------------------------------
    def _build_payload(self, messageInfo):
        req = self._helpers.analyzeRequest(messageInfo)
        url = req.getUrl()
        if url is None:
            return None

        req_bytes = messageInfo.getRequest()
        req_headers = self._headers_dict(req.getHeaders())
        req_body = self._helpers.bytesToString(req_bytes)[req.getBodyOffset():]

        status = None
        resp_headers = {}
        resp_body = ""
        resp_bytes = messageInfo.getResponse()
        if resp_bytes is not None:
            resp = self._helpers.analyzeResponse(resp_bytes)
            status = int(resp.getStatusCode())
            resp_headers = self._headers_dict(resp.getHeaders())
            resp_body = self._helpers.bytesToString(resp_bytes)[resp.getBodyOffset():]

        return {
            "method": str(req.getMethod()),
            "url": str(url),
            "req_headers": req_headers,
            "req_body_b64": base64.b64encode(req_body) if req_body else "",
            "status": status,
            "resp_headers": resp_headers,
            "resp_body_b64": base64.b64encode(resp_body) if resp_body else "",
        }

    @staticmethod
    def _headers_dict(header_list):
        # ilk satir request/status satiridir, atla
        out = {}
        for line in list(header_list)[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def _send(self, payload):
        try:
            data = json.dumps(payload)
            request = urllib2.Request(
                INGEST_URL, data, {"Content-Type": "application/json"}
            )
            urllib2.urlopen(request, timeout=TIMEOUT_SN).read()
        except Exception as exc:
            # AVCI kapaliysa Burp'u yavaslatma; tek satir log yeter
            self._callbacks.printError("AVCI ingest ulasilamadi: " + repr(exc))
