from honeypot import Honeypot


hp = Honeypot('192.168.100.100', False)

print(hp.os)
print(hp.has_tcp(80))
print(hp.get_service_port('http', 'tcp'))

