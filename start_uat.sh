export DETOXIO_API_KEY=`cat ~/.mysecrets/detoxai/api_key.dtx.uat.1`
export DETOXIO_API_HOST=api-uat.detoxio.ai
poetry run python gradio_app.py

