import json

from fastapi.responses import JSONResponse
import tool


def config(id):
    devices_data = tool.load_json("configs/devices.json")
    device_data = devices_data[id]

    if not device_data:
        return

    if not device_data["urls"]:
        return

    if not device_data["template"]:
        return

    try:
        tool.init_parsers()
        tool.update_providers()
        config = tool.load_json("configs/" + device_data["template"])
        nodes = tool.process_subscribes(device_data["urls"])
        final_config = tool.combin_to_config(config, nodes)
        return JSONResponse(json.loads(json.dumps(final_config, indent=4)))
    except Exception as e:
        return JSONResponse(
            json.dumps(
                {
                    "status": "error",
                    "message": e,
                },
                indent=4,
            ),
            status_code=500,
        )
