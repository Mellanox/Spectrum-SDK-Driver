EXTRA_CFLAGS += -DSX_MEMTRACK_MODULE $(SXD_KERNEL_EXTRA_CFLAGS)
obj-m += memtrack.o

memtrack-objs := memtrack_main.o \
                 memtrack_db.o \
                 memtrack_debugfs.o \
                 memtrack_helpers.o \
                 memtrack_malloc.o \
                 memtrack_vmalloc.o \
                 memtrack_kmem_cache.o \
                 memtrack_iomap.o \
                 memtrack_page.o \
                 memtrack_dma.o
