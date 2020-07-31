from stix2 import *
import pandas as pd 
import numpy as np

def getAttackPattern_by_Tactic(fs,tactic):
    tecs = fs.query([Filter('type', '=', 'attack-pattern'),
                Filter('kill_chain_phases.phase_name', '=' , tactic)])

    return tecs


# Load STIX ATT&CK repo
fs = FileSystemSource('../mitre-cti/mobile-attack')

# retrieve STIX 2 objects with ID 
#ap = fs.get("attack-pattern--9d7c32f4-ab39-49dc-8055-8106bc2294a1")
#print(ap)

#
attackpatterns = fs.query([Filter('type', '=', 'attack-pattern')])

print(len(attackpatterns))

# Mobile ATT&CK tactics -- Device Access
tactics = ['initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact','network-effects','remote-service-efforts']

sumT = 0 

all_tecs = dict()

for t in tactics: 
    tecs = getAttackPattern_by_Tactic(fs,t)
    sumT += len(tecs)

    for tec in tecs: 
        all_tecs[tec.name] = tec.kill_chain_phases

print(sumT)
print(len(all_tecs))

df = pd.DataFrame(all_tecs.items())
print(df.shape)

df_attack = pd.DataFrame(columns=tactics)
df_attack['execution'] = ['a','b']
print(df_attack)

#df_attack[t] = np.array(tecs)



# Mobile ATT&CK course-of-actions
course = fs.query([Filter('type', '=', 'course-of-action')])

print(len(course))

for c in course: 
    print(c.name)
    
#print(course[0])

