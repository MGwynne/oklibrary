// Oliver Kullmann, 8.7.2007 (Swansea)
/* Copyright 2007 Oliver Kullmann
This file is part of the OKlibrary. OKlibrary is free software; you can redistribute
it and/or modify it under the terms of the GNU General Public License as published by
the Free Software Foundation and included in this library; either version 3 of the
License, or any later version. */

/*!
  \file LegalIssues/plans/Licence.hpp
  \brief Plans regarding licences

  The basic decision is to use GPLv3 (http://www.fsf.org/licensing/licenses/gpl.html)


  \todo Problems with licence
  <ul>
   <li> Part of the licence must be that the full history is handed down. Is this
   guaranteed by the original text, or do we need to amend it?
    <ol>
     <li> E-mail was sent to FSL. </li>
    </ol>
   </li>
   <li> What about the copyright statements?
    <ol>
     <li> Initially every file has OK's copyright. </li>
     <li> But once other external developers have contributed essentially to some file,
     then perhaps they should also have copyright on this file (that is, the corresponding
     group leader)? Perhaps we should ask the FSF how to handle such situations. </li>
     <li> Perhaps for legal reasons it is not feasible to have such a fractured
     copyright-situation, but then at least perhaps in every plans-directory we have
     a files "contributors.hpp" where just the developers are mentioned which contributed
     to the module (they enter themselves)? </li>
     <li> The possibility, that each files contains its own special copyright list,
     where each contributor enters himself, does not seem feasible to me due to the
     following reasons:
      <ol>
       <li> In each group, there is a hierarchy, and often students and research
       assistants do the work as instructed by their supervisors --- not it wouldn't
       be right that the student or assistant gets the copyright, but it must be
       the supervisor who gets the copyright --- now who shall control this?? </li>
       <li> How to make the distinction: Shall everybody who just corrects a little
       spelling mistake get also the copyright? In our situation, perhaps different
       from traditional (centralised) open-source development, everybody is
       encouraged (and enabled) to do tiny contributions. </li>
       <li> Especially this "continuous model" of tiny steps, a lot of them just
       regarding the documentation, is not compatible with the permanent trouble
       of updating copyrights. </li>
       <li> If in the future due to changed legislation etc. a licence change
       is needed to maintain the open source character, then only the single
       copyright guarantees that it can be done. </li>
       <li> The only thing that could go wrong is that OK, the single copyright holder,
       at some point changes the licence to a proprietary licence, and tries to get
       rich. So well, this possibility seems only fair to me, given that incomparable
       amount of work spent on the OKlibrary. The released code --- and there shall
       be continous releases will always stay free (of course). </li>
       <li> The possibility, that OK creates patents (which would disable others
       to use the library) is excluded by the licence --- if later the licence would
       be changed, then patents could only be issued on later code. </li>
       <li> According the the Berne convention, the contributors do not
       loose their "natural copyright" (as partial authors), it is only
       that I (OK) express *my* copyright. More information is needed here XXX </li>
       <li> Does it make a difference whether contributors submit files already
       with OK's copyright, or perhaps would it be better if the copyright
       would be left blank, and then OK's copyright is filled in? </li>
       <li> What about the contributor's file --- don't we run their into
       similar problems, who shall be entered? And what is the scope of
       contribution --- always the directory below it?? Seems to create also
       trouble. Perhaps we do without it, and leave it to the source control
       to log the contributors (would be more precise)? (But, of course, we
       have the central developers file.) </li>
       <li> Can we make the OKlibrary "officially" available? Or "more
       official"?? Perhaps we need a Sourceforge-account??? The Git-history should
       be well-secured. </li>
       <li> Having each file OK-copyright would emphasise the responsibility
       of OK for the unity of the library. A statement shall be made that OK tries
       his best to maintain and develop all code accepted into the library. </li>
       <li> Also the submissions which are not yet accepted are made visible somewhere. </li>
      </ol>
     </li>
    </ol>
   </li>
   <li> It seems LGPL is suitable; we have to check this (is it compatible
   with all other licenses (for external sources) involved? I guess so). DONE (for the research-platform, where everybody contributes ideas, we need stronger protection) </li>
  </ul>


  \todo Licence documentation
  <ul>
   <li> Basic motivation for the GPL: Research platform. </li>
   <li> Create a special html-page, and link to it from the local documentation page. </li>
  </ul>


  \todo Licence maintenance
  <ul>
   <li> We must make sure, that every new non-data file gets the
   licence statement. </li>
   <li> When external developers check in new files, then those must have the
   OK-copyright etc. clause (otherwise the submission is rejected). </li>
   <li> We should also add the creation-information and licence to
   html-files. </li>
   <li> For every release, the year of the release must be added to every
   file's copyright notice (if not already present). This boils down to
   adding the new year to every copyright statement at the beginning
   of a new year. </li>
   <li> "AddLicence2" is more advanced than "AddLicence1", so the latter
   should be updated. </li>
   <li> Also a third type of script is needed for make-files. </li>
   <li> Important that these scripts tell us about "bad" files. </li>
  </ul>

*/

