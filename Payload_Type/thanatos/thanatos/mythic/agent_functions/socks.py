# POC by Gerar heavily based on medusa 

from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    ParameterGroupInfo,
    TaskArguments,
    MythicTask,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
    SupportedOS,
)

from mythic_container.MythicRPC import SendMythicRPCProxyStart, MythicRPC

from mythic_container.MythicRPC import SendMythicRPCProxyStart, MythicRPC


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Port to bind the SOCKS5 proxy on the Mythic server",
                display_name="Bind port",
                default_value=1080,
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line:
            if self.command_line.strip().startswith("{"):
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    self.add_arg("port", int(self.command_line.strip()))
                except ValueError:
                    raise ValueError("Invalid port number")
        else:
            raise ValueError("Must supply a port")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [port]"
    description = "Start a SOCKS5 proxy listener on the Mythic server that forwards through this agent"
    version = 2
    author = "@RedTeamGPT"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        port = int(task.args.get_arg("port"))

        # Ask Mythic to open a SOCKS port and wire it to this task/callback.
        # For SOCKS: PortType="socks"; only LocalPort matters.
        # LocalPort can be 0 to auto-pick an available port (3.1+).
        actual_port = port
        try:
            resp = await SendMythicRPCProxyStart(
                TaskID=task.id,
                LocalPort=port,
                PortType="socks",
            )
            # Some versions return attributes, some a dict-like
            # Try to capture the real bound port if Mythic auto-assigned it
            if hasattr(resp, "Success") and getattr(resp, "Success"):
                actual_port = getattr(resp, "LocalPort", port)
            elif isinstance(resp, dict) and resp.get("success", resp.get("Status", False)):
                actual_port = resp.get("local_port", port)
        except TypeError:
            # Rare older wrapper signature difference (snake_case kwargs)
            resp = await SendMythicRPCProxyStart(
                task_id=task.id, local_port=port, port_type="socks"
            )
            if isinstance(resp, dict) and resp.get("success"):
                actual_port = resp.get("local_port", port)
        except Exception as e:
            # Fallback to fully dynamic interface if helper isn’t present
            _ = await MythicRPC().execute(
                "proxy_start",
                task_id=task.id,
                local_port=port,
                port_type="socks",
            )

        task.display_params = (
            f"SOCKS5 via Mythic on port {actual_port} (PortType=socks)"
            if actual_port != port
            else f"SOCKS5 via Mythic on port {port}"
        )
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
