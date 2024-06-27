from mitmproxy import http, ctx
import json
import os
import logging
import re
import asyncio

# Domínios que queremos capturar
TARGET_DOMAINS = ["mobi.bb.com.br", "mobi2.bb.com.br", "idhtm.bb.com.br", "idhtm.bb.com.br", "Grafeno", 'mb.banese.b.br', 'mbkcentral.banpara.b.br']
blocked_urls = [
    "idhtm.bb.com.br",
]
requests_data = []

# Python 3.11: replace with TaskGroup
tasks = set()

contar = 0

def response(flow: http.HTTPFlow) -> None:
    response = flow.response
    request = flow.request
    if any(domain in request.pretty_url for domain in TARGET_DOMAINS):
        body_content = response.content.decode('utf-8', errors='replace')
        body_content = body_content.replace("NAO_AUTORIZADO", "AUTORIZADO")
        response.content = body_content.encode('utf-8')
        pattern = re.compile(r"/genoma_api/rest/notifications-settings/\d+$")
        if pattern.search(request.pretty_url):
            body_content = response.content.decode('utf-8', errors='replace')
            print("response", body_content)
            json_obj = json.loads(body_content)
            json_obj["active"] = True
            json_obj["canceled"] = False
            json_obj["needActivation"] = False
            body_content = json.dumps(json_obj)
            print("response", body_content)
            response.content = body_content.encode('utf-8')
        if '/mobile/versions/v1/ios/4.0.45' in request.pretty_url:
            body_content = response.content.decode('utf-8', errors='replace')
            json_obj = json.loads(body_content)
            json_obj['return']["atualizacaoObrigatoria"] = False
            json_obj['return']["atualizado"] = True
            body_content = json.dumps(json_obj)
            response.content = body_content.encode('utf-8')


def request(flow: http.HTTPFlow) -> None:
    request = flow.request
    if any(domain in request.pretty_url for domain in TARGET_DOMAINS):
        if any(domain in request.pretty_url for domain in blocked_urls):
            print(request.content.decode('utf-8', errors='replace'))
            # if('/fp/mobile/conf' in request.pretty_url):
            #    print("passou")
            # else:
            #    flow.response = http.HTTPResponse.make(
            #        403,  # Código de status HTTP
            #        b"Blocked by mitmproxy",  # Corpo da resposta
            #        {"Content-Type": "text/plain"}  # Cabeçalhos HTTP
            #    )

        # Verificar e substituir a versão no User-Agent
        #user_agent = flow.request.headers.get("User-Agent", "")
        #if "7.62.0.0" in user_agent:
        #    flow.request.headers["User-Agent"] = user_agent.replace("7.62.0.0", "9.19.0.6")
#
        #body = request.content.decode('utf-8', errors='replace')
        #body = body.replace('F6B8EA0394E4F7D0E16208D04CB181A8', '860DA0D02AAE3A44D36951E221628B2C')
        #request.content = body.encode('utf-8')
        #try:
        #    if 'Device-Info' in flow.request.headers:
        #        device_info = flow.request.headers['Device-Info']
        #        flow.request.headers['Device-Info'] = device_info.replace("7.62.0.0", "9.19.0.6")
        #except Exception as e:
        #    print(e)
        pattern = re.compile(r"/CentralizadorGamma/api/GerenciarDispositivo/Renomear/\d+$")
        if '/CentralizadorGamma/api/GerenciarDispositivo/Renomear/' in request.pretty_url:
            print(f'[ BAN PARA MUDAR REQUEST ]')
            body_content = request.content.decode('utf-8', errors='replace')
            json_obj = json.loads(body_content)
            json_obj['HabilitadoMultifatorial'] = True
            body_content = json.dumps(json_obj)
            request.content = body_content.encode('utf-8')
        pattern = re.compile(r"/genoma_api/rest/notifications-settings/\d+$")
        if pattern.search(request.pretty_url):
            print("request", request.pretty_url)
            body_content = request.content.decode('utf-8', errors='replace')
            print("request", request.pretty_url, body_content)
            json_obj = json.loads(body_content)
            json_obj["active"] = True
            json_obj["canceled"] = False
            json_obj["needActivation"] = False
            body_content = json.dumps(json_obj)
            print("request", body_content)
            request.content = body_content.encode('utf-8')

        request_entry = {
            "method": request.method,
            "url": request.pretty_url,
            "headers": dict(request.headers),
            "body": request.content.decode('utf-8', errors='replace')
        }
        res = request.content.decode('utf-8', errors='replace')
        try:
            json_obj = json.loads(json.dumps(res))
            # print(json_obj)
        except Exception as e:
            print(e)
        requests_data.append(request_entry)
        create_request_script()

def create_request_script():
    script_lines = [
        "import requests\n",
        "import json\n\n"
    ]

    for i, req in enumerate(requests_data):
        method = req["method"].lower()
        url = req["url"]
        headers = req["headers"]
        body = req["body"]

        headers_str = json.dumps(headers, indent=4)
        script_lines.append(f"def request_{i}():")
        script_lines.append(f"    url = '{url}'")
        script_lines.append(f"    headers = {headers_str}")

        content_type = headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                # Tenta converter o corpo da requisição para JSON
                body_json = json.loads(json.dumps(body))
                # body_str = json.dumps(body_json, indent=4)
                if body_json == "":
                    script_lines.append("    body = {}")
                else:
                    script_lines.append(f"    body = {body_json}")
                script_lines.append(f"    response = requests.{method}(url, headers=headers, json=body)")
            except json.JSONDecodeError:
                # Caso a conversão falhe, trate o corpo como string
                script_lines.append(f"    body = '''{body}'''")
                script_lines.append(f"    response = requests.{method}(url, headers=headers, data=body)")
        elif body:
            script_lines.append(f"    body = '''{body}'''")
            script_lines.append(f"    response = requests.{method}(url, headers=headers, data=body)")
        else:
            script_lines.append(f"    response = requests.{method}(url, headers=headers)")

        script_lines.append(f"    print(response.status_code)")
        script_lines.append(f"    print(response.text)")
        script_lines.append("\n")

    script_lines.append("if __name__ == '__main__':")
    for i in range(len(requests_data)):
        script_lines.append(f"    request_{i}()")

    with open('outRequests.py', 'w') as f:
        f.write('\n'.join(script_lines))

addons = [
    __name__,
]
