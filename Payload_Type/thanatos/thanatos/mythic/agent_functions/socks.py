import base64
from mythic import *
from mythic.payloadtype import *

class ThanatosSocks(PayloadType):
    name = "thanatos/socks"
    description = "SOCKS5 proxy support for Thanatos"
    author = "@M_alphaaa"
    version = "0.1"
    wrapper = False
    wrapped_payloads = []
    supports_linux = True
    supports_windows = True
    supports_macos = False
    c2_profiles = ["http"]
    translation_complete = True

    def __init__(self):
        self.api_settings = {}

    @classmethod
    def get_field_types(cls):
        return {
            'Port': {
                'required': True,
                'description': 'Local port to bind SOCKS5 proxy to',
                'default': '8080',
                'validator': int
            }
        }

class SocksArguments(TaskArguments):
    def __init__(self, task_job):
        super().__init__(task_job)
        self.add_arg("port", "8080", "Port", "Local port to bind SOCKS5 proxy to")

    def finalize(self):
        pass

class SocksTask(TranslationTask):
    def create_tasking(self, task: MythicTask) -> MythicTaskResult:
        # Start SOCKS proxy
        task.args.add_arg("port", task.args.get_arg("port").value, "Port")
        
        # Register SOCKS proxy in Mythic
        proxy_port = int(task.args.get_arg("port").value)
        task_job = TaskJob(task=task)
        task_job.proxy = Proxy(
            proxy_type=ProxyType.SOCKS5,
            proxy_port=proxy_port,
            agent_callback=task.callback
        )
        task_job.proxy.register_proxy()
        
        return MythicTaskResult(
            status=TaskStatus.SUCCESS,
            response=TaskResponse(
                success=True,
                output=f"SOCKS5 proxy started on port {proxy_port}"
            )
        )

    def process_response(self, task: MythicTask, response: TaskResponse):
        # Handle SOCKS data responses from agent
        if "socks" in response.output_data:
            socks_data = response.output_data["socks"]
            callback = task.callback
            
            for socks_msg in socks_data:
                server_id = socks_msg["server_id"]
                data_b64 = socks_msg["data"]
                exit_flag = socks_msg["exit"]
                
                if exit_flag:
                    # Close connection
                    callback.proxy_connections.pop(server_id, None)
                    continue
                
                if data_b64:
                    data = base64.b64decode(data_b64)
                    
                    if server_id not in callback.proxy_connections:
                        # New connection - should have SOCKS handshake already processed
                        # Just store the connection reference
                        callback.proxy_connections[server_id] = None  # Will be filled by Mythic's SOCKS handler
                    else:
                        # Send data to existing connection
                        conn = callback.proxy_connections[server_id]
                        if conn:
                            conn.send(data)

    def process_translation(self, task: MythicTask, response: TaskResponse):
        # This handles incoming SOCKS traffic and translates to agent tasks
        callback = task.callback
        proxy = callback.current_proxy
        
        if not proxy:
            return TaskResponse(
                success=False,
                output="No active SOCKS proxy"
            )
        
        socks_msgs = []
        
        # Process new connections (Mythic handles SOCKS5 handshake)
        for server_id, conn in proxy.get_new_connections().items():
            callback.proxy_connections[server_id] = conn
            
            # Send empty data - agent will handle initial request
            socks_msgs.append({
                "exit": False,
                "server_id": server_id,
                "data": ""
            })
        
        # Process data for existing connections
        for server_id, conn in proxy.get_data().items():
            if server_id in callback.proxy_connections:
                data_b64 = base64.b64encode(conn).decode()
                socks_msgs.append({
                    "exit": False,
                    "server_id": server_id,
                    "data": data_b64
                })
        
        # Process closes
        for server_id in proxy.get_closed_connections():
            socks_msgs.append({
                "exit": True,
                "server_id": server_id,
                "data": ""
            })
            callback.proxy_connections.pop(server_id, None)
        
        if socks_msgs:
            # Create continued_task to send SOCKS data
            continued_task = MythicTask(
                operation=task.operation,
                callback=task.callback,
                command="socks_data",
                params=json.dumps(socks_msgs),
                status=TaskStatus.PROCESSING
            )
            task.callback.add_task(continued_task)
        
        return TaskResponse(
            success=True,
            output="SOCKS data processed"
        )

# Register the task
translation = ThanatosSocks()
translation.register_command(
    command="socks",
    display_name="SOCKS Proxy",
    description="Start SOCKS5 proxy on agent",
    author="@M_alphaaa",
    supported_os=[SupportedOS.Linux, SupportedOS.Windows],
    arguments=SocksArguments,
    task=SocksTask
)
