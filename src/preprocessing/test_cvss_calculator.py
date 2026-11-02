
from cvss import CVSS3, CVSS4

# Example CVSS 3.1 vector from our dataset
vector_v3 = (
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"
)

# Example CVSS 4.0 vector from our dataset
vector_v4 = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
    "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"
)

print("=" * 60)
print("CVSS 3.1 TEST")
print("=" * 60)

try:
    calculator_v3 = CVSS3(vector_v3)
    scores_v3 = calculator_v3.scores()

    print("Vector:", vector_v3)
    print("Scores:", scores_v3)
    print("Base score:", scores_v3[0])
    print("Severity:", calculator_v3.severities()[0])

except Exception as error:
    print("CVSS 3.1 ERROR:", error)


print("\n" + "=" * 60)
print("CVSS 4.0 TEST")
print("=" * 60)

try:
    calculator_v4 = CVSS4(vector_v4)
    scores_v4 = calculator_v4.scores()

    print("Vector:", vector_v4)
    print("Scores:", scores_v4)
    print("Base score:", scores_v4[0])
    print("Severity:", calculator_v4.severities()[0])

except Exception as error:
    print("CVSS 4.0 ERROR:", error)


print("\nCVSS calculator test completed.")
