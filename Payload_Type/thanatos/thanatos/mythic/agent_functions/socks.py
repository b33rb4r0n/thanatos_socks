# POC by Gerar heavily based on medusa and apollo

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

from mythic_container.MythicRPC import (
    SendMythicRPCProxyStartCommand,
    MythicRPCProxyStartMessage,
)

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
    version = 3
    author = "@RedTeamGPT"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        port = int(task.args.get_arg("port"))
        task.display_params = f"SOCKS5 via Mythic on port {port}"

        # If you later add auth params:
        # username = task.args.get_arg("username") or ""
        # password = task.args.get_arg("password") or ""

        # Start the proxy (Command-style API)
        resp = await SendMythicRPCProxyStartCommand(
            MythicRPCProxyStartMessage(
                TaskID=task.id,
                PortType="socks",
                LocalPort=port,
                # Username=username,
                # Password=password,
            )
        )

        if not getattr(resp, "Success", False):
            # Surface the error in the task UI
            task.status = "error"
            task.stderr = getattr(resp, "Error", "Failed to start SOCKS proxy")
        else:
            # If Mythic auto-assigned a port (LocalPort=0), show it
            actual = getattr(resp, "LocalPort", port)
            task.display_params = f"SOCKS5 via Mythic on port {actual}"

        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
