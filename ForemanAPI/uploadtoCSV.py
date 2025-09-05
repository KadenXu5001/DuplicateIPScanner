import gspread
from google.oauth2.service_account import Credentials

class MinerBox:
    def __init__(self, ipSegment, sheetNumber, machinesPerRow=6):
        self.ipSegment = ipSegment #its ip
        self.sheetNumber = sheetNumber #what sheet it is in (ie, the 1st container is sheet 1)
        self.machinesPerRow = machinesPerRow #machines per row in the box

# --- Google Sheets setup ---
SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
creds = Credentials.from_service_account_file('ForemanAPI/foremanCredNew.json', scopes=SCOPES)
gc = gspread.authorize(creds)
sh = gc.open('Foreman Machine Finder Data')

# Mapping ipSegment to MinerBox
ipSegmentToSheetNumber = dict()

def load_sheet_config():
    worksheet = sh.sheet1
    all_values = worksheet.get_all_values()
    for row in all_values[1:]:
        if len(row) < 4:
            continue
        ipSegmentToSheetNumber[int(row[2])] = MinerBox(
            ipSegment=int(row[2]),
            sheetNumber=int(row[0]),
            machinesPerRow=int(row[3])
        )

def get_worksheet_for_miner(miner: MinerBox):
    return sh.get_worksheet(miner.sheetNumber)

def next_in_box_from_number(miner: MinerBox, number):
    """Calculate location string from device number instead of currentNumberOfMiners"""
    superPosition = False
    if "?" in str(number):
        number = int(str(number).split("?")[0])
        superPosition = True

    rackNum = int(number) // 84 + 1
    rowNum = int(number)% 84 // miner.machinesPerRow + 1
    colNum = int(number) % miner.machinesPerRow

    if superPosition:
        return f"{miner.sheetNumber}-{rackNum}-{rowNum}-{colNum}?"
    
    return f"{miner.sheetNumber}-{rackNum}-{rowNum}-{colNum}"

# --- Read new devices ---
def read_new_devices():
    all_devices = []
    with open("new_devices_log.txt", "r") as f:
        for line in f:
            if "Number" not in line:
                continue

            parts = line.strip().split('|')
            if len(parts) >= 4:
                ip_address = parts[1].strip()
                number = parts[5].strip()
                mac_address = parts[3].strip()
                all_devices.append((ip_address, number, mac_address))
    return all_devices

# --- Main upload ---

def upload_devices_to_sheets():
    
    load_sheet_config()
    all_devices = read_new_devices()
    row_number = 1 

    for ip_address, number, mac_address in all_devices:
        try:
            ip_string = ip_address.strip().split(".")[2]

            if(")" in ip_string):
                ip_string = ip_string.split(")")[0]

            ip_segment = int(ip_string)
            
            if ip_segment % 2 == 1:
                ip_segment += 1  # Ensure even segment for box mapping
            

            if("Skipped Machine" in ip_address ):
                new_location = "N/A"
                ipLabel = "Skipped Machine"
            else:
                miner_box = ipSegmentToSheetNumber[ip_segment]
                new_location = next_in_box_from_number(miner_box, number)
                
                ipLabel = ip_address

            
            miner_box = ipSegmentToSheetNumber[ip_segment]
        
            worksheet = get_worksheet_for_miner(miner_box)

            # Update columns A and B for the row corresponding to this device number
            row_number = int(number) + 1 # +1 to account for header row 
            
            worksheet.update(
                values=[[number, ipLabel, mac_address, new_location]],
                range_name=f'A{row_number}:D{row_number}'
            )
            
            print(f"Updated {ip_address} in sheet {miner_box.sheetNumber} at row {row_number}")

        except Exception as e:
            print(f"Failed to upload {ip_address}: {e}")

#upload_devices_to_sheets()

