"""
DPoP 与安全后端相关标准异常。
"""
class PolicyDeniedError(PermissionError):
    """
    策略门拒绝异常：当密钥使用点的上下文校验失败（越权、不在白名单、超频等）时抛出。
    错误码与评审标准 POLICY_DENIED 完全对齐。
    """
    def __init__(self, reason: str, reason_code: str = "POLICY_DENIED"):
        super().__init__(f"[{reason_code}] 策略门拒签: {reason}")
        self.reason_code = reason_code
        self.reason = reason
