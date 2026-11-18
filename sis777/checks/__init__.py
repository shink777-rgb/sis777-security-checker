"""PC-01 to PC-22 check modules, in run order.

Item titles, criteria, guides and self-check questions are Korean: they reproduce the Korean guideline
and are printed on the Korean checklist.
"""
from .pc01 import PC01
from .pc02 import PC02
from .pc03 import PC03
from .pc04 import PC04
from .pc05 import PC05
from .pc06 import PC06
from .pc07 import PC07
from .pc08 import PC08
from .pc09 import PC09
from .pc10 import PC10
from .pc11 import PC11
from .pc12 import PC12
from .pc13 import PC13
from .pc14 import PC14
from .pc15 import PC15
from .pc16 import PC16
from .pc17 import PC17
from .pc18 import PC18
from .pc19 import PC19
from .pc20 import PC20
from .pc21 import PC21
from .pc22 import PC22

ALL = [PC01(), PC02(), PC03(), PC04(), PC05(), PC06(), PC07(), PC08(), PC09(), PC10(), PC11(),
       PC12(), PC13(), PC14(), PC15(), PC16(), PC17(), PC18(), PC19(), PC20(), PC21(), PC22()]
BY_CODE = {c.code: c for c in ALL}

# self-check questions (step 5, P-03)
SELF_CHECKS = [
    {"id": "PC-20", "code": "PC-20", "text": "BIOS/UEFI 부팅(CMOS) 패스워드를 3종 조합 9자리(또는 2종 조합 10자리) 이상으로 설정했습니까?"},
    {"id": "PC-10p", "code": "PC-10", "text": "보안 패치 적용에 대한 내부 관리절차를 수립하여 이행하고 있습니까?"},
    {"id": "PC-11p", "code": "PC-11", "text": "OS 버전(빌드) 관리에 대한 내부 관리절차를 수립하여 이행하고 있습니까?"},
    {"id": "PC-17p", "code": "PC-17", "text": "이동식 미디어 사용에 대한 내부 관리절차를 수립하여 이행하고 있습니까?"},
]
