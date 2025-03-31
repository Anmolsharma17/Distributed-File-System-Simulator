def compare_files(original_path, retrieved_path, verbose=True, max_differences=5):
    try:
        with open(original_path, 'rb') as f1, open(retrieved_path, 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()

        if data1 == data2:
            if verbose:
                print("Files are identical.")
            return {"identical": True, "differences": [], "total_differences": 0}

        differences = []
        total_differences = 0
        try:
            lines1 = data1.decode('utf-8').splitlines()
            lines2 = data2.decode('utf-8').splitlines()
            max_lines = max(len(lines1), len(lines2))
            for i in range(max_lines):
                line1 = lines1[i] if i < len(lines1) else "(no more lines)"
                line2 = lines2[i] if i < len(lines2) else "(no more lines)"
                if line1 != line2:
                    total_differences += 1
                    if len(differences) < max_differences:
                        differences.append((i + 1, line1, line2))
        except UnicodeDecodeError:
            for i, (b1, b2) in enumerate(zip(data1, data2)):
                if b1 != b2:
                    total_differences += 1
                    if len(differences) < max_differences:
                        differences.append((i, b1, b2))
                    break
            if len(data1) != len(data2):
                total_differences += 1
                if len(differences) < max_differences:
                    differences.append((min(len(data1), len(data2)), f"Length mismatch: {len(data1)} vs {len(data2)}", ""))

        return {"identical": False, "differences": differences, "total_differences": total_differences}

    except FileNotFoundError as e:
        print(f"Error: One or both files not found - {e}")
        return {"identical": False, "differences": [], "total_differences": 0}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {"identical": False, "differences": [], "total_differences": 0}

