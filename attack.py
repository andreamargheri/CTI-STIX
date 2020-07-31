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

#print(len(attackpatterns))

# Mobile ATT&CK tactics -- Device Access & 

tactics = ['initial-access','execution','persistence','privilege-escalation','defense-evasion',
'credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact',
'network-effects','remote-service-effects']

#tactics = ['defense-evasion']

sumT = 0 
for t in tactics: 
    tecs = getAttackPattern_by_Tactic(fs,t)
    sumT += len(tecs)

    print(t + ": " + str(len(tecs)))

print(sumT)
#print(len(all_tecs))

#------------------------------------------------------------------
# TECHNIQUES
#------------------------------------------------------------------

print("\n TECHNIQUES \n")

all_tecs = fs.query([Filter('type', '=', 'attack-pattern')])
numberOfRows = len(all_tecs)

print(numberOfRows)

df_attack = pd.DataFrame(index=np.arange(0, numberOfRows),columns=['name','tactics','description','platform'])

#print(all_tecs[0])

sumRev = 0
for i in range(0,len(all_tecs)): 
    #print(i)
    # ignoring revoked techniques from past version
    if(all_tecs[i].revoked):
        sumRev += 1
        continue

    #Get list of tactics
    listTactics = []
    for k in all_tecs[i].kill_chain_phases:
        listTactics.append(k.phase_name)

    df_attack.loc[i] = [all_tecs[i].name,listTactics,all_tecs[i].description,all_tecs[i].x_mitre_platforms]

df_attack.replace('\\n','', regex=True,inplace=True)
df_attack.replace('\n','', regex=True,inplace=True)
df_attack.replace(';',',', regex=True,inplace=True)

df_attack.dropna(inplace=True)
df_attack.reset_index(drop=True,inplace=True)

#print(df_attack.loc[30].description)

print(df_attack.head())
#print(sumRev)
#print(df_attack.shape)

df_attack.to_csv("attack-mobile_tecs.csv",sep=';',index=False)

#------------------------------------------------------------------
# COURSE of ACTION
#------------------------------------------------------------------

print("\n COURSE \n")


# Mobile ATT&CK course-of-actions
course = fs.query([Filter('type', '=', 'course-of-action')])

numberOfRows = len(course)

#print(course[0])

df_course = pd.DataFrame(index=np.arange(0, numberOfRows),columns=['name','description'])

for i in range(0,len(course)): 
    df_course.loc[i] = [course[i].name,course[i].description]

df_course.replace('\\n','', regex=True,inplace=True)
df_course.replace('\n','', regex=True,inplace=True)
df_course.replace(';',',', regex=True,inplace=True)

df_course.dropna(inplace=True)
df_course.reset_index(drop=True,inplace=True)


print(df_course.head())
print(df_course.shape)

df_course.to_csv("attack-mobile_course.csv",sep=';',index=False)


#------------------------------------------------------------------
# RELATIONSHIP COURSE of ACTION
#------------------------------------------------------------------

print("\n RELATIONSHIPS \n")

numberOfRows = 140  #number of mitigations

df_mitigation = pd.DataFrame(index=np.arange(0, numberOfRows),columns=['mitigation','description','mitigated attack'])

index = 0
for i in range(0,len(course)): 
    mitigatedTecs = fs.related_to(course[i],relationship_type='mitigates')

    for m in mitigatedTecs: 
        df_mitigation.loc[index]= [course[i].name,course[i].description,m.name]
        index += 1


print(df_mitigation.head())

print(df_mitigation.shape)

print("Unique mitigations: " + str(len(df_mitigation['mitigation'].unique())))


df_mitigation.replace('\\n','', regex=True,inplace=True)
df_mitigation.replace('\n','', regex=True,inplace=True)
df_mitigation.replace(';',',', regex=True,inplace=True)

df_mitigation.dropna(inplace=True)
df_mitigation.reset_index(drop=True,inplace=True)

df_mitigation.to_csv("attack-mobile_mitigation.csv",sep=';',index=False)


