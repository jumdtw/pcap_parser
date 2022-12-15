# (1)コンパイラ
CC  = g++
# (2)コンパイルオプション
CFLAGS    = -lpcap
# (3)実行ファイル名
TARGET  = a.out
# (4)コンパイル対象のソースコード
SRCS    = main.cpp
# (5)オブジェクトファイル名
OBJS    = $(SRCS:.cpp=.o)


# (9)ターゲットファイル生成
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

# (10)オブジェクトファイル生成
$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)

test:
	./a.out /home/user/buf/read_test.pcap /home/user/buf/gen_test.pcap /home/user/buf/gen_test_change_header.pcap

# (11)"make all"で make cleanとmakeを同時に実施。
all: clean $(OBJS) $(TARGET)
# (12).oファイル、実行ファイル、.dファイルを削除
clean:
	-rm -f $(OBJS) $(TARGET) *.d