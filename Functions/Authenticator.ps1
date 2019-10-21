

<#
Switch ($AuthTextbox.Text) {
    'nadkins' { $Script:LocationID = '458'; $Script:Techname = 'Adkins, Nick' }
    'fballard' { $Script:LocationID = '587'; $Script:Techname = 'Ballard, Frankie' }
    'JBender' { $Script:LocationID = '448'; $Script:Techname = 'Bender, Jonathan' }
    'bishopg' { $Script:LocationID = '508'; $Script:Techname = 'Bishop, Gary' }
    'SBungard' { $Script:LocationID = '463'; $Script:Techname = 'Bungard, Scott' }
    'ncecil' { $Script:LocationID = '459'; $Script:Techname = 'Cecil, Nick' }
    'sconti' { $Script:LocationID = '464'; $Script:Techname = 'Conti, Scott' }
    'jdarby' { $Script:LocationID = '449'; $Script:Techname = 'Darby, Jeffrey' }
    'kdillon' { $Script:LocationID = '452'; $Script:Techname = 'Dillon, Ken' }
    'bdixon' { $Script:LocationID = '595'; $Script:Techname = 'Dixon, Bryan' }
    'sengland' { $Script:LocationID = '465'; $Script:Techname = 'England, Shane' }
    'kylef' { $Script:LocationID = '456'; $Script:Techname = 'Fabricius, Kyle' }
    'bgardner' { $Script:LocationID = '507'; $Script:Techname = 'Gardner, Ben' }
    'ggirton' { $Script:LocationID = '447'; $Script:Techname = 'Girton, Greg' }
    'egreen' { $Script:LocationID = '446'; $Script:Techname = 'Green, Ethan' }
    'jgregory' { $Script:LocationID = '600'; $Script:Techname = 'Gregory, Johnathan' }
    'dheiss' { $Script:LocationID = '443'; $Script:Techname = 'Heiss, David' }
    'ahuffman' { $Script:LocationID = '437'; $Script:Techname = 'Huffman, Ashley' }
    'kking' { $Script:LocationID = '453'; $Script:Techname = 'King, Kyle' }
    'dklatka' { $Script:LocationID = '444'; $Script:Techname = 'Klatka, Dave' }
    'ryanm' { $Script:LocationID = '462'; $Script:Techname = 'Markham, Ryan' }
    'dylan' { $Script:LocationID = '545'; $Script:Techname = 'Markham, Dylan' }
    'kmazanek' { $Script:LocationID = '454'; $Script:Techname = 'Mazanek, Katie' }
    'mmccoy' { $Script:LocationID = '482'; $Script:Techname = 'McCoy, Mathew' }
    'cmcdougal' { $Script:LocationID = '439'; $Script:Techname = 'McDougal, Cole' }
    'kmchugh' { $Script:LocationID = '455'; $Script:Techname = 'McHugh, Kyle' }
    'cmehl' { $Script:LocationID = '440'; $Script:Techname = 'Mehlmann, Christian' }
    'dpittman' { $Script:LocationID = '445'; $Script:Techname = 'Pittman, Dave' }
    'wesp' { $Script:LocationID = '469'; $Script:Techname = 'Powell, Wes' }
    'troyp' { $Script:LocationID = '468'; $Script:Techname = 'Prough, Troy' }
    'crader' { $Script:LocationID = '441'; $Script:Techname = 'Rader, Corey' }
    'broth' { $Script:LocationID = '524'; $Script:Techname = 'Roth, Brandon' }
    'steves' { $Script:LocationID = '467'; $Script:Techname = 'Schlosnagle, Steve' }
    'csingh' { $Script:LocationID = '599'; $Script:Techname = 'Singh, Chris' }
    'pskilton' { $Script:LocationID = '460'; $Script:Techname = 'Skilton, Patrick' }
    'csoska' { $Script:LocationID = '442'; $Script:Techname = 'Soska, Chris' }
    'bsullivan' { $Script:LocationID = '514'; $Script:Techname = 'Sullivan, Brandon' }
    'bsvoboda' { $Script:LocationID = '588'; $Script:Techname = 'Svoboda, Bruce' }
    'jtrovato' { $Script:LocationID = '451'; $Script:Techname = 'Trovato, Jim' }
    'mvanriper' { $Script:LocationID = '457'; $Script:Techname = 'Van Riper, Mae' }
    'nzwickphillips' { $Script:LocationID = '602'; $Script:Techname = 'Zwick-Phillips, Nicole' }
    'Debug' { $Script:LocationID = '378'; $Script:Techname = 'Test Location' }
    'Advanced Graphite' { $Script:LocationID = '528'; $Script:Techname = 'Advanced Graphite Materials' }
    'Community Caregivers' { $Script:LocationID = '525'; $Script:Techname = 'Community Caregivers' }
    'Metis Construction' { $Script:LocationID = '546'; $Script:Techname = 'Metis Construction' } 
    'Refrigeration Sales' { $Script:LocationID = '414'; $Script:Techname = 'Refrigeration Sales' } 
    default {
        $AuthError.Text = 'No user by the name ' + $AuthTextbox.Text + ' exists.'
        $AuthError.Visible = $true
    }
}

#>