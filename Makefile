KMOD=	cacl
SRCS=	cacl.c

# Request vnode_if.h generation - bsd.kmod.mk handles this
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
