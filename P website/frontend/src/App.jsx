import { useState } from 'react'
import reactLogo from './assets/react.svg'
// import './App.css'

import ResponsiveAppBar from './Appbar';

import { Layout } from 'antd';
const { Header, Footer, Sider, Content } = Layout;
import Box from '@mui/material/Box';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';

import TextField from '@mui/material/TextField';

function App() {
  const [count, setCount] = useState(0)
  const [selectInput, setSelectInput] = useState({ reportFamily: '', reportName: '', baselineFamily: '' })

  const handleSelectInputChange = ({ target: { name, value } }) => {
    setSelectInput(prev => ({
      ...prev,
      [name]: value,
    }))
  }


  return (
    <div className="App">
      <ResponsiveAppBar></ResponsiveAppBar>

      <br />
      <Box sx={{ minWidth: 120 }}>
        <InputLabel id="report-family-select-label">Select a family</InputLabel>
        <Select
          labelId="report-family-select-label"
          id="report-family-select"
          name="reportFamily"
          value={selectInput.reportFamily}
          label="family"
          onChange={handleSelectInputChange}
          size="small"
        >
          <MenuItem value=""><em>None</em></MenuItem>
          <MenuItem value={'Dofloo'}>Dofloo</MenuItem>
          <MenuItem value={'Xorddos'}>Xorddos</MenuItem>
          <MenuItem value={'Tsunami'}>Tsunami</MenuItem>
        </Select>
      </Box>
      <Box sx={{ minWidth: 120 }}>
        <InputLabel id="report-select-label">Select a report</InputLabel>
        <Select
          labelId="report-select-label"
          id="report-select"
          name="reportName"
          value={selectInput.reportName}
          label="report"
          onChange={handleSelectInputChange}
          size="small"
        >
          <MenuItem value=""><em>None</em></MenuItem>
          <MenuItem value={'Dofloo-Trendmicro.txt'}>Dofloo-Trendmicro.txt</MenuItem>
          <MenuItem value={'Xorddos-aaa.txt'}>Xorddos-aaa.txt</MenuItem>
          <MenuItem value={'Tsunami-MalwareMustDie.txt'}>Tsunami-MalwareMustDie.txt</MenuItem>
        </Select>
      </Box>
      {/* <div>{selectInput}</div> */}

      <Box sx={{ width: '80%' }}>
        <TextField
          id="outlined-read-only-input"
          label="Content (Read Only)"
          multiline
          sx={{ width: '100%' }}
          maxRows={15}
          defaultValue={"Line1\nLine2"}
          InputProps={{
            readOnly: true,
          }}
        />
      </Box>

    </div>
  )
}

export default App
