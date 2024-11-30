import requests
import base64
import logging


# Hacktor Client
class HacktorClient:
    ATTACK_MODULES_MAP = {
        "OWASP-LLM-APP": "DETOXIO.ATTACKIO",
        "LLM-RISKS": "DETOXIO",
        "JAILBREAK-BENCH": "DETOXIO.JAILBREAKBENCH",
        "ADVBENCH": "DETOXIO.ADVBENCH",
    }

    def __init__(self, api_key):
        self.api_key = api_key
        self.generate_url = "https://api.detoxio.ai/dtx.services.prompts.v1.PromptService/GeneratePrompts"
        self.evaluate_url = "https://api.detoxio.ai/dtx.services.prompts.v1.PromptService/EvaluateModelInteraction"

    def generate(self, attack_module, count=1):
        payload = {
            "count": str(count),
            "filter": {"labels": {}},
        }

        if attack_module:
            lineage = self.ATTACK_MODULES_MAP.get(attack_module, "DETOXIO").lower()
            payload["filter"]["labels"]["lineage"] = lineage

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        try:
            response = requests.post(self.generate_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            if "prompts" in data and len(data["prompts"]) > 0:
                prompt_data = data["prompts"][0]
                prompt_content = prompt_data["data"]["content"]

                # Decode if base64 encoded
                if "_prompt_encoding" in prompt_data.get("sourceLabels", {}) and prompt_data["sourceLabels"]["_prompt_encoding"] == "base64":
                    prompt_content = base64.b64decode(prompt_content).decode("utf-8")

                return prompt_content
            else:
                return "No prompt generated."
        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                logging.error("Forbidden - Invalid API Key")
                return "Forbidden - Invalid API Key - Check your Key"
            logging.error(f"HTTP error occurred: {e}")
            return f"HTTP error: {e}"
        except requests.exceptions.RequestException as e:
            logging.error(f"Error generating prompt: {e}")
            return f"Error generating prompt: {e}"

    def evaluate(self, prompt, response):
        payload = {
            "prompt": {"data": {"content": prompt if prompt else ""}},
            "responses": [{"message": {"content": response}}],
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        try:
            response = requests.post(self.evaluate_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

            # Parse response for any "UNSAFE" threat evaluation statuses
            results = data.get("responses", [])[0].get("results", [])
            unsafe_findings = []

            for result in results:
                threat_class = result["threat"]["threatClass"]
                threat_category = result["threat"]["threatCategory"]
                status = result["status"]
                if "UNSAFE" in status:
                    unsafe_findings.append(
                        {
                            "threatClass": threat_class,
                            "threatCategory": threat_category,
                            "status": status,
                        }
                    )

            if unsafe_findings:
                return {
                    "evaluation": "UNSAFE",
                    "details": unsafe_findings,
                }
            else:
                return {
                    "evaluation": "SAFE",
                    "details": results,
                }

        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                logging.error("Forbidden - Invalid API Key")
                return {"error": "Forbidden - Invalid API Key - Check your Key"}
            logging.error(f"HTTP error occurred: {e}")
            return {"error": f"HTTP error: {e}"}
        except requests.exceptions.RequestException as e:
            logging.error(f"Error evaluating interaction: {e}")
            return {"error": f"Error evaluating interaction: {e}"}
