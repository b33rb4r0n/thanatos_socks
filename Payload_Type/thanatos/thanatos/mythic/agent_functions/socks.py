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

from mythic_container.RPC import SendMythicRPCProxyStartCommand


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Port to bind the SOCKS5 proxy",
                display_name="Bind port",
                default_value=1080,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1
                    )
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            # Allow both JSON and raw integer port
            if self.command_line.startswith("{"):
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    port = int(self.command_line.strip())
                    self.add_arg("port", port)
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
    description = "Start a SOCKS5 proxy listener on the agent that supports dynamic forwarding"
    version = 1
    author = "@RedTeamGPT"
    argument_class = SocksArguments
    attackmapping = ["T1090"]  # Connection Proxy
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        port = task.args.get_arg("port")
        task.display_params = f"Start SOCKS5 proxy on port {port}"

        # Inform Mythic to start proxying `socks_in` / `socks_out` for this agent
        await SendMythicRPCProxyStartCommand(agent_task_id=task.id)

        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        # Placeholder for future result processing
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
