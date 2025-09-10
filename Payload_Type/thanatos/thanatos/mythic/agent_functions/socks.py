# POC by Gerar heavily based on medusa and apollo
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import datetime
import traceback


def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%fZ")


async def _dbg(task_id: str, msg: str):
    """
    Append a debug line to the task output. Visible immediately in the UI.
    """
    line = f"[{_now()}] [socks] {msg}"
    await SendMythicRPCResponseCreate(
        MythicRPCResponseCreateMessage(TaskID=task_id, Response=line.encode())
    )


def _mask(s: str | None) -> str:
    if not s:
        return "(none)"
    return "*" * 8


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
                parameter_group_info=[ParameterGroupInfo(ui_position=0, required=True)],
            ),
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the proxy server for this port.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=False)],
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Port Auth Username",
                type=ParameterType.String,
                description="Require this username to use the SOCKS port (optional).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Port Auth Password",
                type=ParameterType.String,
                description="Require this password to use the SOCKS port (optional).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line or "") == 0:
            raise Exception("Must be passed a port (or JSON) on the command line.")
        try:
            # Try JSON first
            self.load_args_from_json_string(self.command_line)
        except Exception:
            # Fallback: treat the CLI as just a port
            port_str = self.command_line.lower().strip()
            try:
                self.add_arg("port", int(port_str))
            except Exception:
                raise Exception(f"Invalid port number given: {port_str}. Must be an integer.")

        # Validate range
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
    version = 4
    script_only = True  # This is purely server/RPC-driven; nothing goes to the implant
    author = "@RedTeamGPT"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
        dependencies=[],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

        action = (taskData.args.get_arg("action") or "start").lower()
        port = int(taskData.args.get_arg("port"))
        username = taskData.args.get_arg("username")
        password = taskData.args.get_arg("password")

        # Pre-flight debug
        await _dbg(
            taskData.Task.ID,
            f"requested action={action} port={port} "
            f"auth_user={username or '(none)'} auth_pass={_mask(password)}",
        )

        try:
            if action == "start":
                await _dbg(
                    taskData.Task.ID,
                    f"issuing MythicRPCProxyStart (PortType='socks', LocalPort={port})",
                )
                rpc_resp = await SendMythicRPCProxyStartCommand(
                    MythicRPCProxyStartMessage(
                        TaskID=taskData.Task.ID,
                        PortType="socks",
                        LocalPort=port,  # 0 => auto-assign
                        Username=username,
                        Password=password,
                    )
                )

                # Dump key fields that might exist on the response object
                assigned_port = getattr(rpc_resp, "LocalPort", None) or port
                proxy_id = getattr(rpc_resp, "ProxyID", None)
                err_text = rpc_resp.Error if hasattr(rpc_resp, "Error") else None

                await _dbg(
                    taskData.Task.ID,
                    f"RPC start result: Success={rpc_resp.Success} "
                    f"LocalPort={assigned_port} ProxyID={proxy_id} Error={err_text}",
                )

                if not rpc_resp.Success:
                    resp.Success = False
                    resp.TaskStatus = MythicStatus.Error
                    resp.Stderr = err_text or "Failed to start SOCKS proxy"
                    await _dbg(taskData.Task.ID, f"ERROR: {resp.Stderr}")
                else:
                    msg = f"Started SOCKS5 server on port {assigned_port}"
                    await SendMythicRPCResponseCreate(
                        MythicRPCResponseCreateMessage(
                            TaskID=taskData.Task.ID, Response=msg.encode()
                        )
                    )
                    resp.DisplayParams = f"-action start -port {assigned_port}"
                    resp.TaskStatus = MythicStatus.Success
                    resp.Completed = True

            elif action == "stop":
                await _dbg(
                    taskData.Task.ID,
                    f"issuing MythicRPCProxyStop (PortType='socks', Port={port})",
                )
                rpc_resp = await SendMythicRPCProxyStopCommand(
                    MythicRPCProxyStopMessage(
                        TaskID=taskData.Task.ID,
                        PortType="socks",
                        Port=port,
                        Username=username,  # optional
                        Password=password,  # optional
                    )
                )

                err_text = rpc_resp.Error if hasattr(rpc_resp, "Error") else None
                await _dbg(
                    taskData.Task.ID,
                    f"RPC stop result: Success={rpc_resp.Success} Error={err_text}",
                )

                if not rpc_resp.Success:
                    resp.Success = False
                    resp.TaskStatus = MythicStatus.Error
                    resp.Stderr = err_text or "Failed to stop SOCKS proxy"
                    await _dbg(taskData.Task.ID, f"ERROR: {resp.Stderr}")
                else:
                    msg = f"Stopped SOCKS5 server on port {port}"
                    await SendMythicRPCResponseCreate(
                        MythicRPCResponseCreateMessage(
                            TaskID=taskData.Task.ID, Response=msg.encode()
                        )
                    )
                    resp.DisplayParams = f"-action stop -port {port}"
                    resp.TaskStatus = MythicStatus.Success
                    resp.Completed = True

            else:
                err = f"Unknown action: {action}. Use 'start' or 'stop'."
                resp.Success = False
                resp.TaskStatus = MythicStatus.Error
                resp.Stderr = err
                await _dbg(taskData.Task.ID, f"ERROR: {err}")

        except Exception as e:
            tb = traceback.format_exc()
            msg = f"Unhandled exception in socks command: {e}\n{tb}"
            await _dbg(taskData.Task.ID, msg)
            resp.Success = False
            resp.TaskStatus = MythicStatus.Error
            resp.Stderr = str(e)

        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        # All action happens in create_go_tasking via RPC;
        # still return Success to keep pipeline happy.
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
