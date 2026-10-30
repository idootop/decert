"""PoC 作用域约束：签发与代理只允许 *.decert.test。"""

LAB_SUFFIX = ".decert.test"


def is_lab_domain(domain: str) -> bool:
    return bool(domain) and domain.endswith(LAB_SUFFIX)


def require_lab_domain(domain: str) -> str:
    if not is_lab_domain(domain):
        raise ValueError(f"只允许 *{LAB_SUFFIX}，拒绝：{domain!r}")
    return domain
