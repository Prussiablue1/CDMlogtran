input_file = "testing_preprocessed_logs_M1-CVE-2015-5122_windows_h1"   # 输入文件
output_file = "structured_syslog_LA.csv"  # 输出文件

with open(input_file, "r", encoding="utf-8") as fin, open(output_file, "w", encoding="utf-8") as fout:
    for line in fin:
        line = line.strip()
        if not line:
            continue
        fields = line.split(",")
        if fields[-1].strip() == "-LA-":   # 最后一列是 -LA-
            fout.write(line + "\n")

print(f"过滤完成，结果已保存到 {output_file}")
