# POC by Gerar heavily based on medusa and apollo
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                cli_name="port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port to start/stop the SOCKS5 server on (0 = auto-assign).",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=0,
                    required=True
                )]
            ),
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the proxy server for this port.",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=False
                )],
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Port Auth Username",
                type=ParameterType.String,
                description="Require this username to use the SOCKS port (optional).",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=2,
                )]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Port Auth Password",
                type=ParameterType.String,
                description="Require this password to use the SOCKS port (optional).",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=3,
                )]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line or "") == 0:
            # Permitir JSON o CLI simple con el puerto
            raise Exception("Must be passed a port (or JSON) on the command line.")
        try:
            # Intentar parsear como JSON primero
            self.load_args_from_json_string(self.command_line)
        except Exception:
            # Si no es JSON, asumir que es solo el puerto
            port_str = self.command_line.lower().strip()
            try:
                self.add_arg("port", int(port_str))
            except Exception:
                raise Exception(f"Invalid port number given: {port_str}. Must be an integer.")
        # Validación de rango de puerto
        port = self.get_arg("port")
        if not isinstance(port, int) or port < 0 or port > 65535:
            raise Exception(f"Invalid port: {port}. Must be 0–65535.")


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks -port <number> -action {start|stop} [-username u] [-password p]"
    description = (
        "Enable a SOCKS5 proxy on the Mythic server tunneled through this agent. "
        "Compatible with proxychains/proxychains4. Use -port 0 to auto-assign."
    )
    version = 3
    script_only = True  # no se envía nada al implante; todo es RPC en el servidor
    author = "@RedTeamGPT"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
        dependencies=[],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        action = (taskData.args.get_arg("action") or "start").lower()
        port = int(taskData.args.get_arg("port"))
        username = taskData.args.get_arg("username")
        password = taskData.args.get_arg("password")

        if action == "start":
            rpc_resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port,          # 0 => auto-assign
                Username=username,
                Password=password
            ))

            if not rpc_resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = rpc_resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=(rpc_resp.Error or "Failed to start SOCKS proxy").encode()
                ))
            else:
                # Si Mythic asignó automáticamente, mostrar el puerto real
                assigned_port = getattr(rpc_resp, "LocalPort", None) or port
                msg = f"Started SOCKS5 server on port {assigned_port}"
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=msg.encode()
                ))
                response.DisplayParams = f"-action start -port {assigned_port}"
                response.TaskStatus = MythicStatus.Success
                response.Completed = True

        elif action == "stop":
            rpc_resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=port,               # puerto que quieres parar
                Username=username,       # opcional: si configuraste auth al iniciar
                Password=password
            ))

            if not rpc_resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = rpc_resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=(rpc_resp.Error or "Failed to stop SOCKS proxy").encode()
                ))
            else:
                msg = f"Stopped SOCKS5 server on port {port}"
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=msg.encode()
                ))
                response.DisplayParams = f"-action stop -port {port}"
                response.TaskStatus = MythicStatus.Success
                response.Completed = True

        else:
            response.TaskStatus = MythicStatus.Error
            err = f"Unknown action: {action}. Use 'start' or 'stop'."
            response.Stderr = err
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=err.encode()
            ))

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
