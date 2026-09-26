package main

func platformSingBoxConfig(config map[string]interface{}) {
	inbound := config["inbounds"].([]interface{})[0].(map[string]interface{})
	delete(inbound, "interface_name")
	inbound["address"] = []string{"10.99.0.1/30", "fdfe:a128::1/126"}
	inbound["auto_route"] = true

	dns := config["dns"].(map[string]interface{})
	dns["servers"] = []interface{}{map[string]interface{}{"tag": "dns-proxy", "address": "tcp://1.1.1.1", "detour": "proxy"}}
	dns["final"] = "dns-proxy"
}
