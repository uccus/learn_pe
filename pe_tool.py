import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请指定一个pe文件")
        exit(0)

    target_file = sys.argv[1]

    with open(target_file, 'rb') as f:
        h1 = f.read(2)
        print(h1.hex(), "        ", h1)
